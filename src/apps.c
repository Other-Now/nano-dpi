#include "apps.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* app names: id = index (0 = unknown) */
static const char *const app_names[] = {
    "unknown", "youtube", "netflix", "spotify", "twitch", "facebook", "instagram",
    "twitter", "tiktok", "whatsapp", "telegram", "signal", "teams", "zoom",
    "google", "microsoft", "apple", "amazon", "cloudflare", "akamai", "github", "ads"};
#define NAPPS (int)(sizeof app_names / sizeof *app_names)

/* built-in categories, ids 1.. */
static const char *const builtin_cats[] = {
    "none", "streaming", "social", "chat", "web", "cdn", "ads"};

static const struct { const char *suffix; const char *app; const char *cat; } builtin[] = {
    {"youtube.com", "youtube", "streaming"}, {"googlevideo.com", "youtube", "streaming"},
    {"ytimg.com", "youtube", "streaming"}, {"youtu.be", "youtube", "streaming"},
    {"youtube-nocookie.com", "youtube", "streaming"},
    {"netflix.com", "netflix", "streaming"}, {"nflxvideo.net", "netflix", "streaming"},
    {"nflximg.net", "netflix", "streaming"}, {"nflxso.net", "netflix", "streaming"},
    {"nflxext.com", "netflix", "streaming"},
    {"spotify.com", "spotify", "streaming"}, {"scdn.co", "spotify", "streaming"},
    {"spotifycdn.com", "spotify", "streaming"},
    {"twitch.tv", "twitch", "streaming"}, {"ttvnw.net", "twitch", "streaming"},
    {"jtvnw.net", "twitch", "streaming"},
    {"facebook.com", "facebook", "social"}, {"fbcdn.net", "facebook", "social"},
    {"facebook.net", "facebook", "social"}, {"fb.com", "facebook", "social"},
    {"instagram.com", "instagram", "social"}, {"cdninstagram.com", "instagram", "social"},
    {"twitter.com", "twitter", "social"}, {"twimg.com", "twitter", "social"}, {"x.com", "twitter", "social"},
    {"tiktok.com", "tiktok", "social"}, {"tiktokcdn.com", "tiktok", "social"},
    {"tiktokv.com", "tiktok", "social"}, {"byteoversea.com", "tiktok", "social"},
    {"whatsapp.net", "whatsapp", "chat"}, {"whatsapp.com", "whatsapp", "chat"},
    {"telegram.org", "telegram", "chat"}, {"t.me", "telegram", "chat"},
    {"signal.org", "signal", "chat"},
    {"teams.microsoft.com", "teams", "chat"}, {"skype.com", "teams", "chat"},
    {"zoom.us", "zoom", "chat"},
    {"google.com", "google", "web"}, {"googleapis.com", "google", "web"},
    {"gstatic.com", "google", "web"}, {"gvt1.com", "google", "web"},
    {"1e100.net", "google", "web"}, {"googleusercontent.com", "google", "web"},
    {"google-analytics.com", "google", "ads"},
    {"microsoft.com", "microsoft", "web"}, {"live.com", "microsoft", "web"},
    {"office.com", "microsoft", "web"}, {"office365.com", "microsoft", "web"},
    {"windowsupdate.com", "microsoft", "web"}, {"msn.com", "microsoft", "web"},
    {"bing.com", "microsoft", "web"}, {"azureedge.net", "microsoft", "cdn"},
    {"apple.com", "apple", "web"}, {"icloud.com", "apple", "web"},
    {"mzstatic.com", "apple", "web"}, {"apple-dns.net", "apple", "web"},
    {"amazon.com", "amazon", "web"}, {"amazonaws.com", "amazon", "cdn"},
    {"cloudfront.net", "amazon", "cdn"},
    {"cloudflare.com", "cloudflare", "cdn"}, {"cloudflare-dns.com", "cloudflare", "cdn"},
    {"akamaiedge.net", "akamai", "cdn"}, {"akamaihd.net", "akamai", "cdn"},
    {"akamai.net", "akamai", "cdn"},
    {"github.com", "github", "web"}, {"githubusercontent.com", "github", "web"},
    {"doubleclick.net", "ads", "ads"}, {"googlesyndication.com", "ads", "ads"},
    {"adnxs.com", "ads", "ads"},
};

static uint32_t fnv1a(const char *s, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 16777619u; }
    return h;
}

static int grow(apps_t *a) {
    uint32_t ncap = a->cap ? a->cap * 2 : 1024;
    dom_ent_t *ns = calloc(ncap, sizeof *ns);
    if (!ns) return -1;
    for (uint32_t i = 0; i < a->cap; i++) {
        if (!a->slots[i].name) continue;
        uint32_t j = fnv1a(a->slots[i].name, strlen(a->slots[i].name)) & (ncap - 1);
        while (ns[j].name) j = (j + 1) & (ncap - 1);
        ns[j] = a->slots[i];
    }
    free(a->slots);
    a->slots = ns;
    a->cap = ncap;
    return 0;
}

static const dom_ent_t *find(const apps_t *a, const char *s, size_t n) {
    if (!a->cap) return NULL;
    for (uint32_t j = fnv1a(s, n) & (a->cap - 1);; j = (j + 1) & (a->cap - 1)) {
        const dom_ent_t *e = &a->slots[j];
        if (!e->name) return NULL;
        if (strlen(e->name) == n && memcmp(e->name, s, n) == 0) return e;
    }
}

static int insert(apps_t *a, const char *name, uint16_t app, uint8_t cat) {
    if ((a->n + 1) * 4 >= a->cap * 3 && grow(a)) return -1;
    size_t n = strlen(name);
    for (uint32_t j = fnv1a(name, n) & (a->cap - 1);; j = (j + 1) & (a->cap - 1)) {
        dom_ent_t *e = &a->slots[j];
        if (!e->name) {
            e->name = strdup(name);
            e->app = app;
            e->cat = cat;
            a->n++;
            return 1;
        }
        if (strcmp(e->name, name) == 0) {   /* feed overrides category, keeps app */
            if (cat) e->cat = cat;
            if (app) e->app = app;
            return 0;
        }
    }
}

int apps_app_id(const char *name) {
    for (int i = 1; i < NAPPS; i++) if (strcmp(app_names[i], name) == 0) return i;
    return 0;
}

int apps_cat_id(const apps_t *a, const char *name) {
    for (int i = 1; i < a->ncats; i++) if (strcmp(a->cats[i], name) == 0) return i;
    return 0;
}

const char *apps_app_name(uint16_t id) { return id < NAPPS ? app_names[id] : "?"; }
const char *apps_cat_name(const apps_t *a, uint8_t id) { return id < a->ncats ? a->cats[id] : "?"; }

static int add_cat(apps_t *a, const char *name) {
    int id = apps_cat_id(a, name);
    if (id) return id;
    if (a->ncats >= APPS_MAX_CATS) return 0;
    a->cats[a->ncats] = strdup(name);
    return a->ncats++;
}

int apps_init(apps_t *a) {
    memset(a, 0, sizeof *a);
    for (size_t i = 0; i < sizeof builtin_cats / sizeof *builtin_cats; i++)
        a->cats[a->ncats++] = strdup(builtin_cats[i]);
    for (size_t i = 0; i < sizeof builtin / sizeof *builtin; i++)
        if (insert(a, builtin[i].suffix, (uint16_t)apps_app_id(builtin[i].app),
                   (uint8_t)apps_cat_id(a, builtin[i].cat)) < 0) return -1;
    return 0;
}

void apps_free(apps_t *a) {
    for (uint32_t i = 0; i < a->cap; i++) free(a->slots[i].name);
    free(a->slots);
    for (int i = 0; i < a->ncats; i++) free(a->cats[i]);
    memset(a, 0, sizeof *a);
}

int apps_load_feed(apps_t *a, const char *cat, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) { perror(path); return -1; }
    int cid = add_cat(a, cat), n = 0;
    char line[512];
    while (fgets(line, sizeof line, f)) {
        /* accepts "domain", "domain CNAME ." (RPZ) and "0.0.0.0 domain" (hosts) */
        char *s = line;
        if (*s == ';' || *s == '#' || *s == '$' || *s == '@' || isspace((unsigned char)*s)) continue;
        char *tok = strtok(s, " \t\r\n");
        if (!tok) continue;
        if (strcmp(tok, "0.0.0.0") == 0 || strcmp(tok, "127.0.0.1") == 0) {
            tok = strtok(NULL, " \t\r\n");
            if (!tok) continue;
        }
        if (strncmp(tok, "*.", 2) == 0) tok += 2;      /* RPZ wildcard: suffix match covers it */
        size_t l = strlen(tok);
        if (l && tok[l - 1] == '.') tok[--l] = 0;
        if (!l) continue;
        for (char *c = tok; *c; c++) *c = (char)tolower((unsigned char)*c);
        if (insert(a, tok, 0, (uint8_t)cid) >= 0) n++;
    }
    fclose(f);
    return n;
}

void apps_classify(const apps_t *a, const char *host, uint16_t *app, uint8_t *cat) {
    *app = 0;
    *cat = 0;
    size_t n = strlen(host);
    while (n && host[n - 1] == '.') n--;
    /* strip ":port" from HTTP Host values */
    const char *colon = memchr(host, ':', n);
    if (colon && !memchr(colon + 1, ':', n - (size_t)(colon + 1 - host))) n = (size_t)(colon - host);
    const char *s = host;
    while (n) {
        const dom_ent_t *e = find(a, s, n);
        if (e) {
            if (!*cat) *cat = e->cat;
            if (!*app) *app = e->app;
            if (*app && *cat) return;
        }
        const char *dot = memchr(s, '.', n);
        if (!dot) break;
        n -= (size_t)(dot + 1 - s);
        s = dot + 1;
    }
}
