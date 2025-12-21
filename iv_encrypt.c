// iv_encrypt.c developed by BENMANSER Noureddine aka (the-shadow-0
// Built on Linux, shared with love
// Dependencies: libgtk-3-dev gdk-pixbuf2.0-dev libsodium-dev libexif-dev exiftool

#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <gdk-pixbuf/gdk-pixbuf.h>
#include <libexif/exif-data.h>
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#define STEG_MAGIC "STEG"
#define STEG_MAGIC_LEN 4
#define SALT_LEN crypto_pwhash_SALTBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define HEADER_OVERHEAD (STEG_MAGIC_LEN + 1 + SALT_LEN + NONCE_LEN + 4)

#define PW_HASH_OPSLIMIT crypto_pwhash_OPSLIMIT_INTERACTIVE
#define PW_HASH_MEMLIMIT crypto_pwhash_MEMLIMIT_INTERACTIVE
#define PW_HASH_ALG crypto_pwhash_ALG_DEFAULT
#define KEY_LEN crypto_secretbox_KEYBYTES

#define WINDOW_WIDTH 1200
#define WINDOW_HEIGHT 600
#define IMAGE_AREA_W 700
#define IMAGE_AREA_H 560

typedef struct {
    GtkWidget *window;
    GtkWidget *image_widget;
    GtkWidget *image_scroll;
    GtkWidget *metadata_text;
    GtkWidget *message_text;
    GtkWidget *password_entry;
    GtkWidget *btn_save_meta;
    GtkWidget *btn_encrypt;
    GtkWidget *btn_decrypt;
    GtkWidget *btn_open;
    GtkWidget *btn_zoom_in;
    GtkWidget *btn_zoom_out;
    GtkWidget *btn_zoom_reset;
    GtkWidget *status_label;
    gchar *current_file;
    GdkPixbuf *orig_pixbuf;
    double zoom;
} AppState;

typedef struct {
    AppState *app;
    gchar *json_text;
    gchar *target_file;
    GtkWidget *progress_dialog;
    int result;
    gchar *err_msg;
    gchar *fresh_json;
} SaveMetaJob;

static int file_exists(const char *p) {
    struct stat st;
    return (p && stat(p, &st) == 0);
}

static char *read_metadata_json_with_exiftool(const char *filename, GError **gerr) {
    if (!filename) return NULL;
    gchar *argv[] = { "exiftool", "-j", (gchar *)filename, NULL };
    gchar *stdout_data = NULL;
    gchar *stderr_data = NULL;
    int exit_status = 0;
    gboolean ok = g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                              &stdout_data, &stderr_data, &exit_status, NULL);
    if (!ok || exit_status != 0 || !stdout_data) {
        if (gerr) {
            gchar buf[1024];
            snprintf(buf, sizeof(buf), "exiftool failed (status=%d): %s", exit_status, stderr_data ? stderr_data : "(no stderr)");
            *gerr = g_error_new(g_quark_from_string("exiftool"), exit_status, "%s", buf);
        }
        if (stdout_data) g_free(stdout_data);
        if (stderr_data) g_free(stderr_data);
        return NULL;
    }
    char *result = g_strdup(stdout_data);
    g_free(stdout_data);
    if (stderr_data) g_free(stderr_data);
    return result;
}

static int write_metadata_json_to_image(const char *json_text, const char *targetfile, char **err_out) {
    if (!json_text || !targetfile) {
        if (err_out) *err_out = g_strdup("Invalid args");
        return -1;
    }
    char template[] = "/tmp/ivmetaXXXXXX.json";
    int fd = mkstemps(template, 5);
    if (fd < 0) {
        if (err_out) *err_out = g_strdup_printf("mkstemps failed: %s", strerror(errno));
        return -1;
    }
    ssize_t to_write = strlen(json_text);
    ssize_t w = write(fd, json_text, to_write);
    if (w != to_write) {
        close(fd);
        unlink(template);
        if (err_out) *err_out = g_strdup_printf("Failed to write temp JSON: %s", strerror(errno));
        return -1;
    }
    close(fd);

    gchar *arg_json = g_strdup_printf("-json=%s", template);
    gchar *argv[] = { "exiftool", "-overwrite_original", arg_json, (gchar*)targetfile, NULL };
    gchar *stdout_data = NULL;
    gchar *stderr_data = NULL;
    int exit_status = 0;
    gboolean ok = g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH, NULL, NULL,
                              &stdout_data, &stderr_data, &exit_status, NULL);
    g_free(arg_json);
    if (stdout_data) g_free(stdout_data);

    if (!ok || exit_status != 0) {
        if (stderr_data) {
            if (err_out) *err_out = g_strdup(stderr_data);
            g_free(stderr_data);
        } else if (err_out) {
            *err_out = g_strdup_printf("exiftool failed with status %d", exit_status);
        }
        unlink(template);
        return -1;
    }
    if (stderr_data) g_free(stderr_data);
    unlink(template);
    return 0;
}

static void show_error_dialog(GtkWindow *parent, const char *title, const char *message) {
    GtkWidget *d = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_ERROR, GTK_BUTTONS_OK, "%s", message ? message : "(null)");
    if (title) gtk_window_set_title(GTK_WINDOW(d), title);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}
static void show_info_dialog(GtkWindow *parent, const char *title, const char *message) {
    GtkWidget *d = gtk_message_dialog_new(parent, GTK_DIALOG_MODAL, GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", message ? message : "");
    if (title) gtk_window_set_title(GTK_WINDOW(d), title);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static inline int payload_get_bit(const uint8_t *payload, size_t payload_len, size_t bit_idx) {
    size_t byte_index = bit_idx / 8;
    int bit_in_byte = 7 - (bit_idx % 8);
    if (byte_index >= payload_len) return 0;
    return (payload[byte_index] >> bit_in_byte) & 1;
}

static int embed_payload_in_pixbuf(GdkPixbuf *pixbuf, const uint8_t *payload, size_t payload_len) {
    int width = gdk_pixbuf_get_width(pixbuf);
    int height = gdk_pixbuf_get_height(pixbuf);
    int rowstride = gdk_pixbuf_get_rowstride(pixbuf);
    int n_channels = gdk_pixbuf_get_n_channels(pixbuf);
    if (n_channels < 3) return -1;
    size_t capacity_bits = (size_t)width * (size_t)height * 3;
    size_t need_bits = payload_len * 8;
    if (need_bits > capacity_bits) return -1;
    guchar *pixels = gdk_pixbuf_get_pixels(pixbuf);
    size_t bit_idx = 0;
    for (int y = 0; y < height && bit_idx < need_bits; ++y) {
        guchar *row = pixels + y * rowstride;
        for (int x = 0; x < width && bit_idx < need_bits; ++x) {
            guchar *p = row + x * n_channels;
            int bit = payload_get_bit(payload, payload_len, bit_idx++);
            p[0] = (p[0] & 0xFE) | bit;
            if (bit_idx >= need_bits) break;
            bit = payload_get_bit(payload, payload_len, bit_idx++);
            p[1] = (p[1] & 0xFE) | bit;
            if (bit_idx >= need_bits) break;
            bit = payload_get_bit(payload, payload_len, bit_idx++);
            p[2] = (p[2] & 0xFE) | bit;
        }
    }
    return 0;
}

static int extract_payload_from_pixbuf(GdkPixbuf *pixbuf, uint8_t *payload_buf, size_t payload_len) {
    int width = gdk_pixbuf_get_width(pixbuf);
    int height = gdk_pixbuf_get_height(pixbuf);
    int rowstride = gdk_pixbuf_get_rowstride(pixbuf);
    int n_channels = gdk_pixbuf_get_n_channels(pixbuf);
    if (n_channels < 3) return -1;
    size_t capacity_bits = (size_t)width * (size_t)height * 3;
    size_t need_bits = payload_len * 8;
    if (need_bits > capacity_bits) return -1;
    memset(payload_buf, 0, payload_len);
    guchar *pixels = gdk_pixbuf_get_pixels(pixbuf);
    size_t bit_idx = 0;
    for (int y = 0; y < height && bit_idx < need_bits; ++y) {
        guchar *row = pixels + y * rowstride;
        for (int x = 0; x < width && bit_idx < need_bits; ++x) {
            guchar *p = row + x * n_channels;
            int b = p[0] & 1;
            size_t byte_index = bit_idx / 8;
            int pos = 7 - (bit_idx % 8);
            payload_buf[byte_index] |= (b << pos);
            bit_idx++;
            if (bit_idx >= need_bits) break;
            b = p[1] & 1;
            byte_index = bit_idx / 8;
            pos = 7 - (bit_idx % 8);
            payload_buf[byte_index] |= (b << pos);
            bit_idx++;
            if (bit_idx >= need_bits) break;
            b = p[2] & 1;
            byte_index = bit_idx / 8;
            pos = 7 - (bit_idx % 8);
            payload_buf[byte_index] |= (b << pos);
            bit_idx++;
        }
    }
    return 0;
}

static int build_encrypted_payload(const uint8_t *message, size_t message_len, const char *password,
                                   uint8_t **out_payload, size_t *out_payload_len) {
    if (!message || !password || !out_payload || !out_payload_len) return -1;
    uint8_t salt[SALT_LEN];
    uint8_t nonce[NONCE_LEN];
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(nonce, NONCE_LEN);

    uint8_t key[KEY_LEN];
    if (crypto_pwhash(key, KEY_LEN, password, strlen(password), salt,
                      PW_HASH_OPSLIMIT, PW_HASH_MEMLIMIT, PW_HASH_ALG) != 0) {
        return -1;
    }

    size_t c_len = message_len + crypto_secretbox_MACBYTES;
    uint8_t *cipher = malloc(c_len);
    if (!cipher) { sodium_memzero(key, KEY_LEN); return -1; }

    if (crypto_secretbox_easy(cipher, message, message_len, nonce, key) != 0) {
        free(cipher); sodium_memzero(key, KEY_LEN); return -1;
    }

    size_t total = HEADER_OVERHEAD + c_len;
    uint8_t *payload = malloc(total);
    if (!payload) { free(cipher); sodium_memzero(key, KEY_LEN); return -1; }

    size_t pos = 0;
    memcpy(payload + pos, STEG_MAGIC, STEG_MAGIC_LEN); pos += STEG_MAGIC_LEN;
    payload[pos++] = 1;
    memcpy(payload + pos, salt, SALT_LEN); pos += SALT_LEN;
    memcpy(payload + pos, nonce, NONCE_LEN); pos += NONCE_LEN;
    payload[pos++] = (c_len >> 24) & 0xFF;
    payload[pos++] = (c_len >> 16) & 0xFF;
    payload[pos++] = (c_len >> 8) & 0xFF;
    payload[pos++] = (c_len) & 0xFF;
    memcpy(payload + pos, cipher, c_len); pos += c_len;

    free(cipher);
    sodium_memzero(key, KEY_LEN);

    *out_payload = payload;
    *out_payload_len = total;
    return 0;
}

static int parse_and_decrypt_payload(const uint8_t *payload, size_t payload_len, const char *password,
                                     uint8_t **out_message, size_t *out_message_len) {
    if (!payload || !password || payload_len < HEADER_OVERHEAD) return -1;
    size_t pos = 0;
    if (memcmp(payload + pos, STEG_MAGIC, STEG_MAGIC_LEN) != 0) return -1;
    pos += STEG_MAGIC_LEN;
    uint8_t version = payload[pos++]; (void)version;
    const uint8_t *salt = payload + pos; pos += SALT_LEN;
    const uint8_t *nonce = payload + pos; pos += NONCE_LEN;
    uint32_t c_len = (payload[pos] << 24) | (payload[pos+1] << 16) | (payload[pos+2] << 8) | payload[pos+3];
    pos += 4;
    if (pos + c_len > payload_len) return -1;
    const uint8_t *cipher = payload + pos;

    uint8_t key[KEY_LEN];
    if (crypto_pwhash(key, KEY_LEN, password, strlen(password), salt,
                      PW_HASH_OPSLIMIT, PW_HASH_MEMLIMIT, PW_HASH_ALG) != 0) {
        return -1;
    }

    if (c_len < crypto_secretbox_MACBYTES) { sodium_memzero(key, KEY_LEN); return -1; }
    size_t msg_len = c_len - crypto_secretbox_MACBYTES;
    uint8_t *msg = malloc(msg_len + 1);
    if (!msg) { sodium_memzero(key, KEY_LEN); return -1; }

    if (crypto_secretbox_open_easy(msg, cipher, c_len, nonce, key) != 0) {
        free(msg); sodium_memzero(key, KEY_LEN); return -1;
    }
    msg[msg_len] = 0;
    sodium_memzero(key, KEY_LEN);
    *out_message = msg;
    *out_message_len = msg_len;
    return 0;
}

static void update_status(AppState *s) {
    if (!s) return;
    gchar *text;
    if (s->current_file && s->orig_pixbuf) {
        int w = gdk_pixbuf_get_width(s->orig_pixbuf);
        int h = gdk_pixbuf_get_height(s->orig_pixbuf);
        size_t capacity = ((size_t)w * (size_t)h * 3) / 8;
        text = g_strdup_printf("%s — %dx%d — capacity ≈ %zu bytes — zoom %.2fx",
                               s->current_file, w, h, capacity, s->zoom);
    } else if (s->current_file) {
        text = g_strdup_printf("%s", s->current_file);
    } else {
        text = g_strdup("No image loaded");
    }
    gtk_label_set_text(GTK_LABEL(s->status_label), text);
    g_free(text);
}

static char *make_steg_filename(const char *orig) {
    if (!orig) return NULL;
    char *dot = strrchr(orig, '.');
    gchar *out;
    if (dot) {
        size_t prelen = dot - orig;
        gchar *prefix = g_malloc(prelen + 1);
        memcpy(prefix, orig, prelen);
        prefix[prelen] = '\0';
        out = g_strconcat(prefix, "_steg", dot, NULL);
        g_free(prefix);
    } else {
        out = g_strconcat(orig, "_steg.png", NULL);
    }
    return out;
}

static void update_display_scaled(AppState *s) {
    if (!s || !s->orig_pixbuf) return;
    int w = gdk_pixbuf_get_width(s->orig_pixbuf);
    int h = gdk_pixbuf_get_height(s->orig_pixbuf);

    double fit_scale = 1.0;
    if (w > IMAGE_AREA_W || h > IMAGE_AREA_H) {
        double sx = (double)IMAGE_AREA_W / (double)w;
        double sy = (double)IMAGE_AREA_H / (double)h;
        fit_scale = (sx < sy) ? sx : sy;
    }
    double scale = s->zoom;
    if (scale < fit_scale) scale = fit_scale;
    int target_w = (int)(w * scale + 0.5);
    int target_h = (int)(h * scale + 0.5);
    if (target_w < 1) target_w = 1;
    if (target_h < 1) target_h = 1;
    GdkPixbuf *display_pix = gdk_pixbuf_scale_simple(s->orig_pixbuf, target_w, target_h, GDK_INTERP_BILINEAR);
    gtk_image_set_from_pixbuf(GTK_IMAGE(s->image_widget), display_pix);
    g_object_unref(display_pix);
    gtk_widget_set_size_request(s->image_scroll, IMAGE_AREA_W, IMAGE_AREA_H);
    update_status(s);
}

static GtkWidget* create_progress_dialog(GtkWindow *parent, const char *title, const char *label_text, const char *color_hex) {
    GtkWidget *dialog = gtk_dialog_new();
    gtk_window_set_title(GTK_WINDOW(dialog), title ? title : "Working");
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    if (parent) gtk_window_set_transient_for(GTK_WINDOW(dialog), parent);
    gtk_window_set_resizable(GTK_WINDOW(dialog), FALSE);

    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(hbox), 12);
    gtk_container_add(GTK_CONTAINER(content), hbox);

    GtkWidget *spinner = gtk_spinner_new();
    gtk_box_pack_start(GTK_BOX(hbox), spinner, FALSE, FALSE, 0);
    gtk_spinner_start(GTK_SPINNER(spinner));

    gchar *markup = g_strdup_printf("<span foreground=\"%s\">%s</span>", color_hex ? color_hex : "#0f1625ff", label_text ? label_text : "Working...");
    GtkWidget *lab = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lab), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(lab), 0.0);
    gtk_box_pack_start(GTK_BOX(hbox), lab, TRUE, TRUE, 0);

    gtk_widget_show_all(dialog);
    return dialog;
}

static void show_colored_message_dialog(GtkWindow *parent, const char *title, const char *message, const char *color_hex, gboolean is_error) {
    GtkWidget *d = gtk_dialog_new_with_buttons(title ? title : (is_error ? "Error" : "Info"),
                                               parent,
                                               GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                               "_OK",
                                               GTK_RESPONSE_OK,
                                               NULL);
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(d));
    gchar *markup = g_strdup_printf("<span foreground=\"%s\">%s</span>", color_hex ? color_hex : (is_error ? "#f3e9e9ff" : "#0f1625ff"), message ? message : "");
    GtkWidget *lab = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(lab), markup);
    g_free(markup);
    gtk_label_set_xalign(GTK_LABEL(lab), 0.0);
    gtk_container_add(GTK_CONTAINER(content), lab);
    gtk_widget_show_all(d);
    gtk_dialog_run(GTK_DIALOG(d));
    gtk_widget_destroy(d);
}

static gboolean save_meta_finish(gpointer user_data);

static gpointer save_meta_thread(gpointer user_data) {
    SaveMetaJob *job = (SaveMetaJob*)user_data;
    job->result = -1;
    job->err_msg = NULL;
    job->fresh_json = NULL;

    char *err = NULL;
    int rc = write_metadata_json_to_image(job->json_text, job->target_file, &err);
    if (rc != 0) {
        job->result = rc;
        job->err_msg = err ? err : g_strdup("Unknown error writing metadata");
        g_idle_add(save_meta_finish, job);
        return NULL;
    }

    GError *gerr = NULL;
    char *fresh = read_metadata_json_with_exiftool(job->target_file, &gerr);
    if (fresh) {
        job->fresh_json = fresh;
    } else {
        if (gerr) {
            job->err_msg = g_strdup(gerr->message);
            g_error_free(gerr);
        }
    }
    job->result = 0;
    g_idle_add(save_meta_finish, job);
    return NULL;
}

static gboolean save_meta_finish(gpointer user_data) {
    SaveMetaJob *job = (SaveMetaJob*)user_data;
    AppState *s = job->app;

    if (job->progress_dialog) {
        gtk_widget_destroy(job->progress_dialog);
        job->progress_dialog = NULL;
    }

    if (job->result == 0) {
        if (job->fresh_json) {
            GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->metadata_text));
            gtk_text_buffer_set_text(buf, job->fresh_json, -1);
        }
        show_colored_message_dialog(GTK_WINDOW(s->window), "Metadata written", "Metadata successfully written into image.", "#111827", FALSE);
    } else {
        const char *em = job->err_msg ? job->err_msg : "Failed to write metadata.";
        show_colored_message_dialog(GTK_WINDOW(s->window), "exiftool error", em, "#660000", TRUE);
    }

    if (job->json_text) g_free(job->json_text);
    if (job->target_file) g_free(job->target_file);
    if (job->err_msg) g_free(job->err_msg);
    if (job->fresh_json) g_free(job->fresh_json);
    g_free(job);

    return G_SOURCE_REMOVE;
}

static void on_save_metadata_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    if (!s || !s->current_file) {
        show_colored_message_dialog(GTK_WINDOW(s->window), "Error", "No image loaded.", "#660000", TRUE);
        return;
    }
    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->metadata_text));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(buf, &start, &end);
    gchar *text = gtk_text_buffer_get_text(buf, &start, &end, FALSE);
    if (!text || strlen(text) == 0) {
        if (text) g_free(text);
        show_colored_message_dialog(GTK_WINDOW(s->window), "Error", "Metadata JSON is empty.", "#660000", TRUE);
        return;
    }
    SaveMetaJob *job = g_new0(SaveMetaJob, 1);
    job->app = s;
    job->json_text = text;
    job->target_file = g_strdup(s->current_file);
    job->progress_dialog = create_progress_dialog(GTK_WINDOW(s->window), "Writing metadata", "Writing metadata to image — please wait...", "#111827");

    GThread *t = g_thread_new("save-meta-thread", save_meta_thread, job);
    if (!t) {
        if (job->progress_dialog) { gtk_widget_destroy(job->progress_dialog); job->progress_dialog = NULL; }
        show_colored_message_dialog(GTK_WINDOW(s->window), "Error", "Failed to spawn worker thread.", "#660000", TRUE);
        if (job->json_text) g_free(job->json_text);
        if (job->target_file) g_free(job->target_file);
        g_free(job);
        return;
    }
    g_thread_unref(t);
}

static void on_open_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    GtkWidget *chooser = gtk_file_chooser_dialog_new("Open image", GTK_WINDOW(s->window),
                                                     GTK_FILE_CHOOSER_ACTION_OPEN,
                                                     "_Cancel", GTK_RESPONSE_CANCEL,
                                                     "_Open", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    if (gtk_dialog_run(GTK_DIALOG(chooser)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(chooser));
        if (filename) {
            if (s->current_file) g_free(s->current_file);
            s->current_file = g_strdup(filename);
            s->zoom = 1.0;
            if (s->orig_pixbuf) { g_object_unref(s->orig_pixbuf); s->orig_pixbuf = NULL; }

            GError *err = NULL;
            GdkPixbuf *pix = gdk_pixbuf_new_from_file(filename, &err);
            if (!pix) {
                show_error_dialog(GTK_WINDOW(s->window), "Load error", err ? err->message : "Failed to load image");
                if (err) g_error_free(err);
            } else {
                s->orig_pixbuf = pix;
                update_display_scaled(s);
                GError *gerr = NULL;
                char *json = read_metadata_json_with_exiftool(filename, &gerr);
                if (json) {
                    GtkTextBuffer *mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->metadata_text));
                    gtk_text_buffer_set_text(mbuf, json, -1);
                    g_free(json);
                } else if (gerr) {
                    show_error_dialog(GTK_WINDOW(s->window), "exiftool error", gerr->message);
                    g_error_free(gerr);
                }
            }
            g_free(filename);
        }
    }
    gtk_widget_destroy(chooser);
}

static void on_embed_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    if (!s->orig_pixbuf || !s->current_file) { show_error_dialog(GTK_WINDOW(s->window), "Error", "No image loaded."); return; }

    GtkTextBuffer *mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->message_text));
    GtkTextIter start, end;
    gtk_text_buffer_get_bounds(mbuf, &start, &end);
    gchar *msg = gtk_text_buffer_get_text(mbuf, &start, &end, FALSE);
    const char *password = gtk_entry_get_text(GTK_ENTRY(s->password_entry));
    if (!msg || strlen(msg) == 0) { if (msg) g_free(msg); show_error_dialog(GTK_WINDOW(s->window), "Error", "Please enter a message to embed."); return; }
    if (!password || strlen(password) == 0) { g_free(msg); show_error_dialog(GTK_WINDOW(s->window), "Error", "Please enter a password."); return; }

    uint8_t *payload = NULL;
    size_t payload_len = 0;
    if (build_encrypted_payload((uint8_t*)msg, strlen(msg), password, &payload, &payload_len) != 0) {
        g_free(msg);
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Failed to build encrypted payload.");
        return;
    }
    g_free(msg);

    GdkPixbuf *copy = gdk_pixbuf_copy(s->orig_pixbuf);
    if (!copy) { free(payload); show_error_dialog(GTK_WINDOW(s->window), "Error", "Failed to copy image."); return; }

    int width = gdk_pixbuf_get_width(copy), height = gdk_pixbuf_get_height(copy);
    size_t capacity_bytes = ((size_t)width * (size_t)height * 3) / 8;
    if (payload_len > capacity_bytes) {
        free(payload);
        g_object_unref(copy);
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Image too small for message+encryption.");
        return;
    }

    if (embed_payload_in_pixbuf(copy, payload, payload_len) != 0) {
        free(payload);
        g_object_unref(copy);
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Embedding failed.");
        return;
    }

    char *stegfile = make_steg_filename(s->current_file);
    GError *gerr = NULL;
    if (!gdk_pixbuf_save(copy, stegfile, "png", &gerr, NULL)) {
        free(payload);
        g_object_unref(copy);
        show_error_dialog(GTK_WINDOW(s->window), "Save error", gerr ? gerr->message : "Failed to save steg file");
        if (gerr) g_error_free(gerr);
        g_free(stegfile);
        return;
    }

    GtkTextBuffer *meta_buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->metadata_text));
    GtkTextIter mstart, mend;
    gtk_text_buffer_get_bounds(meta_buf, &mstart, &mend);
    gchar *meta_text = gtk_text_buffer_get_text(meta_buf, &mstart, &mend, FALSE);

    char *exif_err = NULL;
    if (meta_text && strlen(meta_text) > 0) {
        if (write_metadata_json_to_image(meta_text, stegfile, &exif_err) != 0) {
            show_error_dialog(GTK_WINDOW(s->window), "exiftool error", exif_err ? exif_err : "Failed to write metadata to steg file");
            if (exif_err) g_free(exif_err);
        }
    }
    if (meta_text) g_free(meta_text);

    free(payload);
    g_object_unref(copy);

    if (s->current_file) g_free(s->current_file);
    s->current_file = g_strdup(stegfile);
    s->zoom = 1.0;
    if (s->orig_pixbuf) { g_object_unref(s->orig_pixbuf); s->orig_pixbuf = NULL; }
    GError *err = NULL;
    GdkPixbuf *pix = gdk_pixbuf_new_from_file(stegfile, &err);
    if (!pix) {
        show_error_dialog(GTK_WINDOW(s->window), "Load error", err ? err->message : "Failed to load steg image");
        if (err) g_error_free(err);
    } else {
        s->orig_pixbuf = pix;
        update_display_scaled(s);
    }

    show_info_dialog(GTK_WINDOW(s->window), "Done", stegfile);
    g_free(stegfile);
}

static void on_extract_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    if (!s->orig_pixbuf || !s->current_file) { show_error_dialog(GTK_WINDOW(s->window), "Error", "No image loaded."); return; }

    const char *password = gtk_entry_get_text(GTK_ENTRY(s->password_entry));
    if (!password || strlen(password) == 0) { show_error_dialog(GTK_WINDOW(s->window), "Error", "Please enter a password."); return; }

    int w = gdk_pixbuf_get_width(s->orig_pixbuf), h = gdk_pixbuf_get_height(s->orig_pixbuf);
    size_t capacity_bytes = ((size_t)w * (size_t)h * 3) / 8;
    if (capacity_bytes < HEADER_OVERHEAD) { show_error_dialog(GTK_WINDOW(s->window), "Error", "Image too small to contain a payload."); return; }

    uint8_t *header = malloc(HEADER_OVERHEAD);
    if (!header) return;
    if (extract_payload_from_pixbuf(s->orig_pixbuf, header, HEADER_OVERHEAD) != 0) {
        free(header);
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Failed to read payload header.");
        return;
    }
    if (memcmp(header, STEG_MAGIC, STEG_MAGIC_LEN) != 0) {
        free(header);
        show_info_dialog(GTK_WINDOW(s->window), "No payload", "No stego payload detected in image.");
        return;
    }
    size_t pos = STEG_MAGIC_LEN + 1 + SALT_LEN + NONCE_LEN;
    uint32_t c_len = (header[pos] << 24) | (header[pos+1] << 16) | (header[pos+2] << 8) | header[pos+3];
    free(header);

    size_t total_payload_len = HEADER_OVERHEAD + c_len;
    if (total_payload_len > capacity_bytes) {
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Declared payload too large for image capacity.");
        return;
    }

    uint8_t *payload_buf = malloc(total_payload_len);
    if (!payload_buf) return;
    if (extract_payload_from_pixbuf(s->orig_pixbuf, payload_buf, total_payload_len) != 0) {
        free(payload_buf);
        show_error_dialog(GTK_WINDOW(s->window), "Error", "Failed to extract payload bytes.");
        return;
    }

    uint8_t *plain = NULL;
    size_t plain_len = 0;
    if (parse_and_decrypt_payload(payload_buf, total_payload_len, password, &plain, &plain_len) != 0) {
        free(payload_buf);
        show_error_dialog(GTK_WINDOW(s->window), "Decrypt error", "Failed to decrypt payload (wrong password or corrupted).");
        return;
    }

    GtkTextBuffer *txtbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(s->message_text));
    gtk_text_buffer_set_text(txtbuf, (const char*)plain, plain_len);

    free(plain);
    free(payload_buf);

    show_info_dialog(GTK_WINDOW(s->window), "Success", "Message extracted and decrypted.");
}

static void on_zoom_in_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    s->zoom *= 1.25;
    if (s->zoom > 10.0) s->zoom = 10.0;
    update_display_scaled(s);
}
static void on_zoom_out_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    s->zoom /= 1.25;
    if (s->zoom < 0.05) s->zoom = 0.05;
    update_display_scaled(s);
}
static void on_zoom_reset_clicked(GtkButton *btn, gpointer userdata) {
    AppState *s = (AppState*)userdata;
    s->zoom = 1.0;
    update_display_scaled(s);
}

static void apply_css(void) {
    GtkCssProvider *provider = gtk_css_provider_new();
    const char *css =
        "window { background-color: #0b1220; color: #f9fafcff; }\n"
        "headerbar { background-color: #091226; color: #ffffffff; padding: 6px; }\n"
        "label { color: #f5fafdff; }\n"
        "button { background-color: #1c1e1fff !important; border-radius: 8px; padding: 6px 10px; }\n"
        "button label, button GtkLabel { color: #0b1720 !important; font-weight: 700 !important; }\n"
        "textview { background-color: #e2e5e9ff; color: #f6f8fcff; border-radius: 6px; padding: 6px; }\n"
        "textview.mono { font-family: monospace; }\n";
    gtk_css_provider_load_from_data(provider, css, -1, NULL);
    GdkScreen *screen = gdk_screen_get_default();
    gtk_style_context_add_provider_for_screen(screen, GTK_STYLE_PROVIDER(provider), GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(provider);
}
static void set_button_text_color(GtkButton *btn, const char *hex_color) {
    if (!GTK_IS_BUTTON(btn) || !hex_color) return;
    GtkWidget *child = gtk_bin_get_child(GTK_BIN(btn));
    if (!child || !GTK_IS_LABEL(child)) return;
    const char *plain = gtk_label_get_text(GTK_LABEL(child));
    if (!plain) return;
    gchar *markup = g_strdup_printf("<span foreground=\"%s\" weight=\"bold\">%s</span>", hex_color, plain);
    gtk_label_set_markup(GTK_LABEL(child), markup);
    g_free(markup);
}
static void force_all_button_label_colors(GtkWidget *widget, const char *hex_color) {
    if (!widget) return;
    if (GTK_IS_BUTTON(widget)) set_button_text_color(GTK_BUTTON(widget), hex_color);
    if (GTK_IS_CONTAINER(widget)) {
        GList *children = gtk_container_get_children(GTK_CONTAINER(widget));
        for (GList *l = children; l != NULL; l = l->next) {
            force_all_button_label_colors(GTK_WIDGET(l->data), hex_color);
        }
        g_list_free(children);
    }
}

static AppState *app_state_new(void) {
    AppState *s = g_new0(AppState, 1);
    s->current_file = NULL;
    s->orig_pixbuf = NULL;
    s->zoom = 1.0;

    s->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_default_size(GTK_WINDOW(s->window), WINDOW_WIDTH, WINDOW_HEIGHT);
    gtk_window_set_resizable(GTK_WINDOW(s->window), FALSE);
    gtk_window_set_title(GTK_WINDOW(s->window), "IV_Encrypt");

    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(header), TRUE);
    gtk_header_bar_set_title(GTK_HEADER_BAR(header), "IV_Encrypt");
    gtk_header_bar_set_subtitle(GTK_HEADER_BAR(header), "Metadata • Stego");
    gtk_window_set_titlebar(GTK_WINDOW(s->window), header);

    GtkWidget *min_btn = gtk_button_new_from_icon_name("window-minimize-symbolic", GTK_ICON_SIZE_BUTTON);
    g_signal_connect_swapped(min_btn, "clicked", G_CALLBACK(gtk_window_iconify), s->window);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), min_btn);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_container_add(GTK_CONTAINER(s->window), root);
    gtk_container_set_border_width(GTK_CONTAINER(root), 10);

    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_box_pack_start(GTK_BOX(root), hbox, TRUE, TRUE, 0);

    GtkWidget *left_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_size_request(left_vbox, 460, -1);
    gtk_box_pack_start(GTK_BOX(hbox), left_vbox, FALSE, FALSE, 0);

    GtkWidget *meta_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(meta_label), "<span size='large' weight='bold'>Metadata (JSON)</span>");
    gtk_box_pack_start(GTK_BOX(left_vbox), meta_label, FALSE, FALSE, 0);

    s->metadata_text = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(s->metadata_text), GTK_WRAP_NONE);
    gtk_widget_set_size_request(s->metadata_text, 440, 220);
    gtk_style_context_add_class(gtk_widget_get_style_context(s->metadata_text), "mono");
    GtkWidget *meta_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_widget_set_size_request(meta_scroll, 440, 220);
    gtk_container_add(GTK_CONTAINER(meta_scroll), s->metadata_text);
    gtk_box_pack_start(GTK_BOX(left_vbox), meta_scroll, FALSE, FALSE, 0);

    s->btn_save_meta = gtk_button_new_with_label("Save metadata");
    gtk_widget_set_tooltip_text(s->btn_save_meta, "Write edited metadata JSON back into the image (exiftool)");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_save_meta), "primary");
    gtk_box_pack_start(GTK_BOX(left_vbox), s->btn_save_meta, FALSE, FALSE, 0);

    GtkWidget *sep = gtk_separator_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_box_pack_start(GTK_BOX(left_vbox), sep, FALSE, FALSE, 6);

    GtkWidget *msg_label = gtk_label_new(NULL);
    gtk_label_set_markup(GTK_LABEL(msg_label), "<span size='large' weight='bold'>Message</span>");
    gtk_box_pack_start(GTK_BOX(left_vbox), msg_label, FALSE, FALSE, 0);

    s->message_text = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(s->message_text), GTK_WRAP_WORD_CHAR);
    gtk_widget_set_size_request(s->message_text, 440, 200);
    gtk_style_context_add_class(gtk_widget_get_style_context(s->message_text), "mono");
    GtkWidget *msg_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(msg_scroll), s->message_text);
    gtk_box_pack_start(GTK_BOX(left_vbox), msg_scroll, FALSE, FALSE, 0);

    GtkWidget *pw_label = gtk_label_new("Password for (Encrypt/Decrypt):");
    gtk_box_pack_start(GTK_BOX(left_vbox), pw_label, FALSE, FALSE, 0);
    s->password_entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(s->password_entry), FALSE);
    gtk_box_pack_start(GTK_BOX(left_vbox), s->password_entry, FALSE, FALSE, 0);

    GtkWidget *action_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(left_vbox), action_row, FALSE, FALSE, 0);

    s->btn_encrypt = gtk_button_new_with_label("Encrypt");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_encrypt), "warning");
    gtk_box_pack_start(GTK_BOX(action_row), s->btn_encrypt, TRUE, TRUE, 0);

    s->btn_decrypt = gtk_button_new_with_label("Decrypt");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_decrypt), "success");
    gtk_box_pack_start(GTK_BOX(action_row), s->btn_decrypt, TRUE, TRUE, 0);

    s->btn_open = gtk_button_new_with_label("Open");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_open), "icon");
    gtk_box_pack_start(GTK_BOX(left_vbox), s->btn_open, FALSE, FALSE, 0);

    GtkWidget *right_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_box_pack_start(GTK_BOX(hbox), right_vbox, TRUE, TRUE, 0);

    s->image_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(s->image_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_size_request(s->image_scroll, IMAGE_AREA_W, IMAGE_AREA_H);
    gtk_box_pack_start(GTK_BOX(right_vbox), s->image_scroll, TRUE, TRUE, 0);

    s->image_widget = gtk_image_new();
    gtk_widget_set_size_request(s->image_widget, IMAGE_AREA_W, IMAGE_AREA_H);
    gtk_container_add(GTK_CONTAINER(s->image_scroll), s->image_widget);

    GtkWidget *zoom_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_pack_start(GTK_BOX(right_vbox), zoom_row, FALSE, FALSE, 0);

    s->btn_zoom_in = gtk_button_new_with_label("Zoom In");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_zoom_in), "icon");
    gtk_box_pack_start(GTK_BOX(zoom_row), s->btn_zoom_in, FALSE, FALSE, 0);

    s->btn_zoom_out = gtk_button_new_with_label("Zoom Out");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_zoom_out), "icon");
    gtk_box_pack_start(GTK_BOX(zoom_row), s->btn_zoom_out, FALSE, FALSE, 0);

    s->btn_zoom_reset = gtk_button_new_with_label("Reset Zoom");
    gtk_style_context_add_class(gtk_widget_get_style_context(s->btn_zoom_reset), "icon");
    gtk_box_pack_start(GTK_BOX(zoom_row), s->btn_zoom_reset, FALSE, FALSE, 0);

    s->status_label = gtk_label_new("No image loaded");
    gtk_box_pack_start(GTK_BOX(root), s->status_label, FALSE, FALSE, 0);

    g_signal_connect(s->btn_save_meta, "clicked", G_CALLBACK(on_save_metadata_clicked), s);
    g_signal_connect(s->btn_open, "clicked", G_CALLBACK(on_open_clicked), s);
    g_signal_connect(s->btn_encrypt, "clicked", G_CALLBACK(on_embed_clicked), s);
    g_signal_connect(s->btn_decrypt, "clicked", G_CALLBACK(on_extract_clicked), s);
    g_signal_connect(s->btn_zoom_in, "clicked", G_CALLBACK(on_zoom_in_clicked), s);
    g_signal_connect(s->btn_zoom_out, "clicked", G_CALLBACK(on_zoom_out_clicked), s);
    g_signal_connect(s->btn_zoom_reset, "clicked", G_CALLBACK(on_zoom_reset_clicked), s);

    gtk_widget_set_tooltip_text(s->metadata_text, "Edit the full JSON metadata produced by exiftool. Save when ready.");
    gtk_widget_set_tooltip_text(s->message_text, "Message to encrypt and embed, or where extracted message appears.");

    apply_css();

    return s;
}

static void fix_button_labels_on_show(GtkWidget *window) {
    force_all_button_label_colors(window, "#111827");
}

int main(int argc, char **argv) {
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }
    gtk_init(&argc, &argv);

    AppState *app = app_state_new();

    if (argc >= 2) {
        const char *f = argv[1];
        if (file_exists(f)) {
            app->current_file = g_strdup(f);
            app->zoom = 1.0;
            GError *err = NULL;
            GdkPixbuf *pix = gdk_pixbuf_new_from_file(f, &err);
            if (!pix) {
                show_error_dialog(GTK_WINDOW(app->window), "Load error", err ? err->message : "Failed to load image");
                if (err) g_error_free(err);
            } else {
                app->orig_pixbuf = pix;
                update_display_scaled(app);
                GError *gerr = NULL;
                char *json = read_metadata_json_with_exiftool(f, &gerr);
                if (json) {
                    GtkTextBuffer *mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(app->metadata_text));
                    gtk_text_buffer_set_text(mbuf, json, -1);
                    g_free(json);
                } else if (gerr) {
                    show_error_dialog(GTK_WINDOW(app->window), "exiftool error", gerr->message);
                    g_error_free(gerr);
                }
            }
        } else {
            show_error_dialog(GTK_WINDOW(app->window), "File not found", "Provided file not found.");
        }
    }

    g_signal_connect(app->window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    gtk_widget_show_all(app->window);
    fix_button_labels_on_show(app->window);
    gtk_main();

    if (app->orig_pixbuf) g_object_unref(app->orig_pixbuf);
    if (app->current_file) g_free(app->current_file);
    g_free(app);
    return 0;
}

