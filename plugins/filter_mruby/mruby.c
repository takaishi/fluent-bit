#include <fluent-bit/flb_config.h>
#include <msgpack.h>
#include <fluent-bit.h>
#include "mruby_config.h"

#define FLB_FILTER_MODIFIED 1
#define FLB_FILTER_NOTOUCH  2

//struct flb_filter_plugin {
//  int flags;
//  char *name;
//  char *description;
//
//  int (*cb_init) (struct flb_filter_instance *, struct flb_config *, void *);
//  int (*cb_filter) (void *, size_t, char *, int, void **, size_t *, struct flb_filter_instance *, void *, struct flb_config *);
//  int (*cb_exit) (void *, struct flb_config *);
//};

static int cb_mruby_init(struct flb_filter_instance *f_ins,
                         struct flb_config *config,
                         void *data)
{

    struct mruby_filter *ctx;

    ctx = flb_calloc(1, sizeof(struct mruby_filter));
    ctx->mrb = mrb_open();
   return 0;
}

static int cb_mruby_filter(void *data, size_t bytes, char *tag, int tag_len, void **out_buf, size_t *out_bytes, struct flb_filter_instance *f_ins, void *filter_context, struct flb_config *config)
{
   return FLB_FILTER_MODIFIED;
}

static int cb_mruby_exit(void *data, struct flb_config *config)
{
 return 0;
}

struct flb_filter_plugin filter_mruby_plugin = {
    .name         = "mruby",
    .description  = "mruby Scriptiong Filter",
    .cb_init      = cb_mruby_init,
    .cb_exit      = cb_mruby_filter,
    .cb_exit      = cb_mruby_exit,
    .flags        = 0
};