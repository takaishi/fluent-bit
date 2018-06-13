#include <fluent-bit/flb_config.h>
#include <msgpack.h>
#include <fluent-bit.h>
#include <fluent-bit/flb_time.h>
#include <mruby/hash.h>
#include <mruby/include/mruby/variable.h>
#include <mruby/include/mruby/array.h>

#include "mruby_config.h"

#define FLB_FILTER_MODIFIED 1
#define FLB_FILTER_NOTOUCH  2

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
            asprintf(&str, "(string) %s\n", RSTRING_PTR( value ));
            break;
        }
        case MRB_TT_HASH: {
            char *inspect = mrb_str_to_cstr(core, mrb_inspect(core, value));
            asprintf(&str, "(hash) %s\n", inspect);
        }
    }

    return str;
}

void mrb_tommsgpack(mrb_state *state, mrb_value value, msgpack_packer *pck)
{
    enum mrb_vtype type = mrb_type(value);

    if (mrb_undef_p(value) || mrb_nil_p(value)) {
        printf("undef or nil");
    }

    switch (type) {
        case MRB_TT_HASH: {
            mrb_value keys = mrb_hash_keys(state, value);
            int len = RARRAY_LEN(keys);

            msgpack_pack_map(pck, len);
            for (int i = 0; i < len; i++) {
                mrb_value key = mrb_ary_ref(state, keys, i);
                char *k;
                k = RSTRING_PTR(key),
                msgpack_pack_str(pck, strlen(k));
                msgpack_pack_str_body(pck, k, strlen(k));
                char *v;
                v = RSTRING_PTR(mrb_hash_get(state, value, key));
                msgpack_pack_str(pck, strlen(v));
                msgpack_pack_str_body(pck, v, strlen(v));
            }
        }
    }

}

mrb_value msgpack_obj_to_mrb_value(mrb_state *mrb, msgpack_object *record)
{
    int size, i;
    char *s;
    mrb_value mrb_v = mrb_hash_new(mrb);

    switch(record->type) {
        case MSGPACK_OBJECT_STR:
            s = flb_malloc(record->via.str.size);
            strncpy(s, record->via.str.ptr, record->via.str.size);
            break;
        case MSGPACK_OBJECT_MAP:
            size = record->via.map.size;
            if (size != 0) {
                msgpack_object_kv *p = record->via.map.ptr;
                for (i = 0; i < size; i++) {
                    msgpack_object *key = &(p+i)->key;
                    msgpack_object *val = &(p+i)->val;

                    char *k = flb_malloc(key->via.str.size);
                    char *v = flb_malloc(val->via.str.size);
                    strncpy(k, key->via.str.ptr, key->via.str.size);
                    strncpy(v, val->via.str.ptr, val->via.str.size);
                    k[key->via.str.size] = '\0';
                    v[val->via.str.size] = '\0';
                    mrb_hash_set(mrb, mrb_v, mrb_str_new_cstr(mrb, k), mrb_str_new_cstr(mrb, v));
                }
            }
            break;
        default:
            break;
    }
    return mrb_v;
}

static int cb_mruby_init(struct flb_filter_instance *f_ins,
                         struct flb_config *config,
                         void *data)
{
    struct mruby_filter *ctx;
    struct mf_t *mf;
    mrb_value obj;

    // Create mrb_state
    mf = flb_calloc(1, sizeof(struct mf_t));
    mf->mrb = mrb_open();
    mf->mrb->ud = mf;

    // Create context
    ctx = flb_calloc(1, sizeof(struct mruby_filter));
    ctx->mf = mf;
    ctx->call = flb_filter_get_property("call", f_ins);

    // Load mruby script
    FILE* fp = fopen(flb_filter_get_property("script", f_ins), "r");
    obj = mrb_load_file(mf->mrb, fp);
    ctx->mf->obj = obj;
    fclose(fp);

    // Set context
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
    struct mruby_filter *ctx = filter_context;

    size_t off = 0;
    double ts;
    msgpack_object *p;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_unpacked result;
    struct flb_time t;
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
        ctx->mf->tag = tag;
        ctx->mf->record = p;

        mrb_value *mrb;
        mrb = ctx->mf->mrb;


        mrb_value value;

        value = mrb_funcall(mrb, ctx->mf->obj, ctx->call, 3, mrb_str_new_cstr(mrb, tag), mrb_float_value(mrb, ts), msgpack_obj_to_mrb_value(mrb, p));

        msgpack_pack_array(&tmp_pck, 2);
        flb_time_from_double(&t, ts);
        flb_time_append_to_msgpack(&t, &tmp_pck, 0);
        mrb_tommsgpack(mrb, value, &tmp_pck);

        msgpack_sbuffer_destroy(&data_sbuf);
    }
    msgpack_unpacked_destroy(&result);

    *out_buf   = tmp_sbuf.data;
    *out_bytes = tmp_sbuf.size;

    return FLB_FILTER_MODIFIED;
}

static int cb_mruby_exit(void *data, struct flb_config *config)
{
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