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

char *em_mrb_value_to_str(mrb_state *core, mrb_value value) {
    char *str;
    enum mrb_vtype type = mrb_type(value);

    if (mrb_undef_p(value) || mrb_nil_p(value)) {
        printf("undef or nil");
        asprintf(&str, "(nil)");
        return str;
    }

    switch (type) {
        case MRB_TT_FIXNUM: {
            asprintf(&str, "(integer) %lld\n",mrb_fixnum(value));
            break;

        }
        case MRB_TT_STRING: {
            asprintf(&str, "(string) %s\n", mrb_str_to_cstr(core, value));
            break;
        }
    }

    return str;
}

static int cb_mruby_init(struct flb_filter_instance *f_ins,
                         struct flb_config *config,
                         void *data)
{
    printf("[DEBUG] cb_mruby_init\n");

   return 0;
}

static int cb_mruby_filter(void *data, size_t bytes,
                           char *tag, int tag_len,
                           void **out_buf, size_t *out_bytes,
                           struct flb_filter_instance *f_ins,
                           void *filter_context,
                           struct flb_config *config)
{
    printf("[DEBUG] cb_mruby_filter\n");

    struct mruby_filter *ctx;

    ctx = flb_calloc(1, sizeof(struct mruby_filter));
    ctx->mrb = mrb_open();

    mrb_value value;
    mrbc_context *mrb_cxt;

    char *str;
    char *res;

    str = "1 + 1";
    mrb_cxt = mrbc_context_new(ctx->mrb);
    value = mrb_load_string_cxt(ctx->mrb, str, mrb_cxt);
    res = em_mrb_value_to_str(ctx, value);

    printf("%s\n", res);
   return FLB_FILTER_MODIFIED;
}

static int cb_mruby_exit(void *data, struct flb_config *config)
{
    printf("[DEBUG] cb_mruby_exit\n");
 return 0;
}

struct flb_filter_plugin filter_mruby_plugin = {
    .name         = "mruby",
    .description  = "mruby Scriptiong Filter",
    .cb_init      = cb_mruby_init,
    .cb_filter    = cb_mruby_filter,
    .cb_exit      = cb_mruby_exit,
    .flags        = 0
};