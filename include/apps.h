/* apps.h - map a hostname to an application and a content category.
 *
 * Lookup walks the name from most to least specific ("a.b.example.com",
 * "b.example.com", "example.com", "com") so a feed entry for one exact host
 * beats a broad app suffix. Built-in app suffixes are compiled in; category
 * feeds (plain domain lists or RPZ zone files, e.g. the URLhaus feed that
 * nano-dns uses) are loaded at start-up.
 */
#ifndef NANODPI_APPS_H
#define NANODPI_APPS_H
#include <stdint.h>

#define APPS_MAX_CATS 32

typedef struct {
    char    *name;
    uint16_t app;
    uint8_t  cat;
} dom_ent_t;

typedef struct {
    dom_ent_t *slots;
    uint32_t   cap, n;
    int        ncats;
    char      *cats[APPS_MAX_CATS];   /* cat id -> name; id 0 = "none" */
} apps_t;

int         apps_init(apps_t *a);            /* loads built-in app table */
void        apps_free(apps_t *a);
/* load a feed; every domain in it gets category `cat` (created if new).
 * Returns number of domains loaded, -1 on error. */
int         apps_load_feed(apps_t *a, const char *cat, const char *path);
void        apps_classify(const apps_t *a, const char *host, uint16_t *app, uint8_t *cat);
int         apps_app_id(const char *name);   /* 0 if unknown */
int         apps_cat_id(const apps_t *a, const char *name);
const char *apps_app_name(uint16_t id);
const char *apps_cat_name(const apps_t *a, uint8_t id);

#endif
