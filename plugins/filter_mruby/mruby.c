#include <fluent-bit/flb_config.h>
#include <msgpack.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>

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
        case MRB_TT_FLOAT: {
            asprintf(&str, "(float) %lf\n",mrb_float(value));
            break;

        }
        case MRB_TT_STRING: {
            asprintf(&str, "(string) %s\n", mrb_str_to_cstr(core, value));
            break;
        }
    }

    return str;
}

mrb_value em_mrb_method_count(mrb_state *mrb, mrb_value self)
{
    mf *mf_obj = (mf *)mrb->ud;
    int count = mf_obj->count;

    return mrb_fixnum_value(count);
}

mrb_value em_mrb_method_timestamp(mrb_state *mrb, mrb_value self)
{
    mf *mf_obj = (mf *)mrb->ud;
    double ts = mf_obj->ts;

    return mrb_float_value(mrb, ts);
}

static int cb_mruby_init(struct flb_filter_instance *f_ins,
                         struct flb_config *config,
                         void *data)
{
    printf("[DEBUG] cb_mruby_init\n");
    struct mruby_filter *ctx;

    struct mf_t *mf;
    mf = flb_calloc(1, sizeof(struct mf_t));
    mf->count = 0;
    mf->mrb = mrb_open();
    mf->mrb->ud = mf;

    ctx = flb_calloc(1, sizeof(struct mruby_filter));
    ctx->mf = mf;

    struct RClass *class;
    class = mrb_define_class(ctx->mf->mrb, "Em", ctx->mf->mrb->object_class);

    mrb_define_class_method(ctx->mf->mrb, class, "count", em_mrb_method_count, MRB_ARGS_NONE());
    mrb_define_class_method(ctx->mf->mrb, class, "timestamp", em_mrb_method_timestamp, MRB_ARGS_NONE());

    flb_filter_set_context(f_ins, ctx);


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

    struct mruby_filter *ctx = filter_context;

    size_t off = 0;
    double ts;
    msgpack_object *p;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    struct flb_time t;
    char *str;
    char *res;

    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        msgpack_packer data_pck;
        msgpack_sbuffer data_sbuf;

        msgpack_sbuffer_init(&data_sbuf);
        msgpack_packer_init(&data_pck, &data_sbuf, msgpack_sbuffer_write);

        flb_time_pop_from_msgpack(&t, &result, &p);
        ts = flb_time_to_double(&t);

        ctx->mf->ts = ts;
        mrb_value value;
        mrbc_context *mrb_cxt;

        str = "p Em.timestamp";
        mrb_cxt = mrbc_context_new(ctx->mf->mrb);
        value = mrb_load_string_cxt(ctx->mf->mrb, str, mrb_cxt);
        res = em_mrb_value_to_str(ctx, value);
        ctx->mf->count++;


    }
    printf("res = %s\n", res);
    return FLB_FILTER_MODIFIED;
}

static int cb_mruby_exit(void *data, struct flb_config *config)
{
    printf("[DEBUG] cb_mruby_exit\n");
    struct mruby_filter *ctx;

    ctx = data;
    mrb_close(ctx->mf->mrb);
    free(ctx->mf);
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