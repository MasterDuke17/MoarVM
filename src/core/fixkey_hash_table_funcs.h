/* These are private. We need them out here for the inline functions. Use those.
 */
/* See comments in hash_allocate_common (and elsewhere) before changing the
 * load factor, or FIXKEY_MIN_SIZE_BASE_2 or MVM_HASH_INITIAL_BITS_IN_METADATA,
 * and test with assertions enabled. The current choices permit certain
 * optimisation assumptions in parts of the code. */
#define MVM_FIXKEY_HASH_LOAD_FACTOR 0.75
MVM_STATIC_INLINE MVMuint32 MVM_fixkey_hash_official_size(const struct MVMFixKeyHashTableControl *control) {
    return 1 << (MVMuint32)control->official_size_log2;
}
/* -1 because...
 * probe distance of 1 is the correct bucket.
 * hence for a value whose ideal slot is the last bucket, it's *in* the official
 * allocation.
 * probe distance of 2 is the first extra bucket beyond the official allocation
 * probe distance of 255 is the 254th beyond the official allocation.
 */
MVM_STATIC_INLINE MVMuint32 MVM_fixkey_hash_allocated_items(const struct MVMFixKeyHashTableControl *control) {
    return MVM_fixkey_hash_official_size(control) + control->max_probe_distance_limit - 1;
}
MVM_STATIC_INLINE MVMuint32 MVM_fixkey_hash_kompromat(const struct MVMFixKeyHashTableControl *control) {
    assert(!(control->cur_items == 0 && control->max_items == 0));
    return MVM_fixkey_hash_official_size(control) + control->max_probe_distance - 1;
}
MVM_STATIC_INLINE MVMuint32 MVM_fixkey_hash_max_items(const struct MVMFixKeyHashTableControl *control) {
    return MVM_fixkey_hash_official_size(control) * MVM_FIXKEY_HASH_LOAD_FACTOR;
}
MVM_STATIC_INLINE MVMuint8 *MVM_fixkey_hash_metadata(const struct MVMFixKeyHashTableControl *control) {
    return (MVMuint8 *) control + sizeof(struct MVMFixKeyHashTableControl);
}
MVM_STATIC_INLINE MVMuint8 *MVM_fixkey_hash_entries(const struct MVMFixKeyHashTableControl *control) {
    return (MVMuint8 *) control - sizeof(MVMString ***);
}

/* Frees the entire contents of the hash, leaving you just the hashtable itself,
   which you allocated (heap, stack, inside another struct, wherever) */
void MVM_fixkey_hash_demolish(MVMThreadContext *tc, MVMFixKeyHashTable *hashtable);
/* and then free memory if you allocated it */

/* Call this before you use the hashtable, to initialise it.
 * Doesn't allocate memory - you can embed the struct within a larger struct if
 * you wish.
 */
void MVM_fixkey_hash_build(MVMThreadContext *tc, MVMFixKeyHashTable *hashtable, MVMuint32 entry_size);

MVM_STATIC_INLINE int MVM_fixkey_hash_is_empty(MVMThreadContext *tc,
                                               MVMFixKeyHashTable *hashtable) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    return !control || control->cur_items == 0;
}

/* UNCONDITIONALLY creates a new hash entry with the given key and value.
 * Doesn't check if the key already exists. Use with care. */
void *MVM_fixkey_hash_insert_nocheck(MVMThreadContext *tc,
                                     MVMFixKeyHashTable *hashtable,
                                     MVMString *key);


MVM_STATIC_INLINE struct MVM_hash_loop_state
MVM_fixkey_hash_create_loop_state(MVMThreadContext *tc,
                                  struct MVMFixKeyHashTableControl *control,
                                  MVMString *key) {
    MVMuint64 hash_val = MVM_string_hash_code(tc, key);
    struct MVM_hash_loop_state retval;
    retval.entry_size = sizeof(MVMString ***);
    retval.metadata_increment = 1 << control->metadata_hash_bits;
    retval.metadata_hash_mask = retval.metadata_increment - 1;
    retval.probe_distance_shift = control->metadata_hash_bits;
    retval.max_probe_distance = control->max_probe_distance;

    unsigned int used_hash_bits
        = hash_val >> (control->key_right_shift - control->metadata_hash_bits);
    retval.probe_distance = retval.metadata_increment | (used_hash_bits & retval.metadata_hash_mask);
    MVMHashNumItems bucket = used_hash_bits >> control->metadata_hash_bits;
    if (!control->metadata_hash_bits) {
        assert(retval.probe_distance == 1);
        assert(retval.metadata_hash_mask == 0);
        assert(bucket == used_hash_bits);
    }

    retval.entry_raw = MVM_fixkey_hash_entries(control) - bucket * retval.entry_size;
    retval.metadata = MVM_fixkey_hash_metadata(control) + bucket;
    return retval;
}

MVM_STATIC_INLINE void *MVM_fixkey_hash_fetch_nocheck(MVMThreadContext *tc,
                                                      MVMFixKeyHashTable *hashtable,
                                                      MVMString *key) {
    if (MVM_fixkey_hash_is_empty(tc, hashtable)) {
        return NULL;
    }

    struct MVMFixKeyHashTableControl *control = hashtable->table;
    struct MVM_hash_loop_state ls = MVM_fixkey_hash_create_loop_state(tc, control, key);

    while (1) {
        if (*ls.metadata == ls.probe_distance) {
            MVMString ***entry = (MVMString ***) ls.entry_raw;
            /* A struct, which starts with an MVMString * */
            MVMString **indirection = *entry;
            if (*indirection == key
                || (MVM_string_graphs_nocheck(tc, key) == MVM_string_graphs_nocheck(tc, *indirection)
                    && MVM_string_substrings_equal_nocheck(tc, key, 0,
                                                           MVM_string_graphs_nocheck(tc, key),
                                                           *indirection, 0))) {
                return indirection;
            }
        }
        /* There's a sentinel at the end. This will terminate: */
        else if (*ls.metadata < ls.probe_distance) {
            /* So, if we hit 0, the bucket is empty. "Not found".
               If we hit something with a lower probe distance then...
               consider what would have happened had this key been inserted into
               the hash table - it would have stolen this slot, and the key we
               find here now would have been displaced further on. Hence, the key
               we seek can't be in the hash table. */
            return NULL;
        }
        ls.probe_distance += ls.metadata_increment;
        ++ls.metadata;
        ls.entry_raw -= ls.entry_size;
        assert(ls.probe_distance < (ls.max_probe_distance + 2) * ls.metadata_increment);
        assert(ls.metadata < MVM_fixkey_hash_metadata(control) + MVM_fixkey_hash_official_size(control) + MVM_fixkey_hash_max_items(control));
        assert(ls.metadata < MVM_fixkey_hash_metadata(control) + MVM_fixkey_hash_official_size(control) + 256);
    }
}

/* Looks up entry for key, creating it if necessary.
 * Returns the structure we indirect to.
 * If it's freshly allocated, then *entry is NULL (you need to fill this in)
 * and everything else is uninitialised.
 * This might seem like a quirky API, but it's intended to fill a common pattern
 * we have, and the use of NULL key avoids needing two return values.
 * DON'T FORGET to fill in the NULL key. */
void *MVM_fixkey_hash_lvalue_fetch_nocheck(MVMThreadContext *tc,
                                           MVMFixKeyHashTable *hashtable,
                                           MVMString *key);
/* iterators are stored as unsigned values, metadata index plus one.
 * This is clearly an internal implementation detail. Don't cheat.
 */

/* Only call this if MVM_fixkey_hash_at_end returns false. */
MVM_STATIC_INLINE MVMFixKeyHashIterator MVM_fixkey_hash_next_nocheck(MVMThreadContext *tc,
                                                               MVMFixKeyHashTable *hashtable,
                                                               MVMFixKeyHashIterator iterator) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    /* Whilst this looks like it can be optimised to word at a time skip ahead.
     * (Beware of endianness) it isn't easy *yet*, because one can overrun the
     * allocated buffer, and that makes ASAN very excited. */
    while (--iterator.pos > 0) {
        if (MVM_fixkey_hash_metadata(control)[iterator.pos - 1]) {
            return iterator;
        }
    }
    return iterator;
}

MVM_STATIC_INLINE MVMFixKeyHashIterator MVM_fixkey_hash_next(MVMThreadContext *tc,
                                                       MVMFixKeyHashTable *hashtable,
                                                       MVMFixKeyHashIterator iterator) {
#if HASH_DEBUG_ITER
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    if (iterator.owner != control->ht_id) {
        MVM_oops(tc, "MVM_fixkey_hash_next called with an iterator from a different hash table: %016" PRIx64 " != %016" PRIx64,
                 iterator.owner, control->ht_id);
    }
    /* "the usual case" is that the iterator serial number  matches the hash
     * serial number.
     * As we permit deletes at the current iterator, we also track whether the
     * last mutation on the hash was a delete, and if so record where. Hence,
     * if the hash serial has advanced by one, and the last delete was at this
     * iterator's current bucket position, that's OK too. */
    if (!(iterator.serial == control->serial
          || (iterator.serial == control->serial - 1 &&
              iterator.pos == control->last_delete_at))) {
        MVM_oops(tc, "MVM_fixkey_hash_next called with an iterator with the wrong serial number: %u != %u",
                 iterator.serial, control->serial);
    }
#endif

    if (iterator.pos == 0) {
        MVM_oops(tc, "Calling fixkey_hash_next when iterator is already at the end");
    }

    return MVM_fixkey_hash_next_nocheck(tc, hashtable, iterator);
}

MVM_STATIC_INLINE MVMFixKeyHashIterator MVM_fixkey_hash_first(MVMThreadContext *tc,
                                                        MVMFixKeyHashTable *hashtable) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    MVMFixKeyHashIterator iterator;

    if (!control) {
        /* This hash has not even been built yet. We return an iterator that is
         * already "at the end" */
#if HASH_DEBUG_ITER
        iterator.owner = iterator.serial = 0;
#endif
        iterator.pos = 0;
        return iterator;
    }

#if HASH_DEBUG_ITER
    iterator.owner = control->ht_id;
    iterator.serial = control->serial;
#endif

    if (control->cur_items == 0) {
        /* The hash is empty. No need to do the work to find the "first" item
         * when we know that there are none. Return an iterator at the end. */
        iterator.pos = 0;
        return iterator;
    }

    iterator.pos = MVM_fixkey_hash_kompromat(control);

    if (MVM_fixkey_hash_metadata(control)[iterator.pos - 1]) {
        return iterator;
    }
    return MVM_fixkey_hash_next(tc, hashtable, iterator);
}

MVM_STATIC_INLINE MVMFixKeyHashIterator MVM_fixkey_hash_start(MVMThreadContext *tc,
                                                        MVMFixKeyHashTable *hashtable) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    MVMFixKeyHashIterator retval;
    if (MVM_UNLIKELY(!control)) {
#if HASH_DEBUG_ITER
        retval.owner = retval.serial = 0;
#endif
        retval.pos = 1;
        return retval;
    }

#if HASH_DEBUG_ITER
    retval.owner = control->ht_id;
    retval.serial = control->serial;
#endif
    retval.pos = MVM_fixkey_hash_kompromat(control) + 1;
    return retval;
}

MVM_STATIC_INLINE int MVM_fixkey_hash_at_start(MVMThreadContext *tc,
                                            MVMFixKeyHashTable *hashtable,
                                            MVMFixKeyHashIterator iterator) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    if (MVM_UNLIKELY(!control)) {
        return iterator.pos == 1;
    }
#if HASH_DEBUG_ITER
    if (iterator.owner != control->ht_id) {
        MVM_oops(tc, "MVM_fixkey_hash_at_start called with an iterator from a different hash table: %016" PRIx64 " != %016" PRIx64,
                 iterator.owner, control->ht_id);
    }
    if (iterator.serial != control->serial) {
        MVM_oops(tc, "MVM_fixkey_hash_at_start called with an iterator with the wrong serial number: %u != %u",
                 iterator.serial, control->serial);
    }
#endif
    return iterator.pos == MVM_fixkey_hash_kompromat(control) + 1;
}

/* Only call this if MVM_fixkey_hash_at_end returns false. */
MVM_STATIC_INLINE void *MVM_fixkey_hash_current_nocheck(MVMThreadContext *tc,
                                                     MVMFixKeyHashTable *hashtable,
                                                     MVMFixKeyHashIterator iterator) {
    struct MVMFixKeyHashTableControl *control = hashtable->table;
    assert(MVM_fixkey_hash_metadata(control)[iterator.pos - 1]);
    return MVM_fixkey_hash_entries(control) - control->entry_size * (iterator.pos - 1);
}

/* FIXME - this needs a better name: */
MVM_STATIC_INLINE void *MVM_fixkey_hash_current(MVMThreadContext *tc,
                                             MVMFixKeyHashTable *hashtable,
                                             MVMFixKeyHashIterator iterator) {
#if HASH_DEBUG_ITER
    const struct MVMFixKeyHashTableControl *control = hashtable->table;
    if (iterator.owner != control->ht_id) {
        MVM_oops(tc, "MVM_fixkey_hash_current called with an iterator from a different hash table: %016" PRIx64 " != %016" PRIx64,
                 iterator.owner, control->ht_id);
    }
    if (iterator.serial != control->serial) {
        MVM_oops(tc, "MVM_fixkey_hash_current called with an iterator with the wrong serial number: %u != %u",
                 iterator.serial, control->serial);
    }
#endif

    /* This is MVM_fixkey_hash_at_end without the HASH_DEBUG_ITER checks duplicated. */
    if (MVM_UNLIKELY(iterator.pos == 0)) {
        /* Bother. This seems to be part of our de-facto API. */
        return NULL;
    }

    return MVM_fixkey_hash_current_nocheck(tc, hashtable, iterator);
}
