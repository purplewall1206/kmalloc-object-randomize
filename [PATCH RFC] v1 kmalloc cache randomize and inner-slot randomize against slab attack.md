

![kmalloc-randomize-graph.png](../media/kmalloc-randomize-graph.png)


---
Signed-off-by: Wang Zi-cheng <wzc@smail.nju.edu.cn>
---
RFC: kmalloc caches randomize and inner-slot randomize against slab attacks

Sorry I put introduction at the bottom of the previous patch and it disappered , 
so I re-send it.

Hello, everyone! I wrote a prototype to defend against slab manipulation 
attacks and requesting your comments.

RATIONALE:

In the previous patch, I quote from the paper 'slake'
> both victim and spray objects are allocated in kmalloc and controlled by clear syscall.

victim and spray objects are necessary for exploiting and quantity is limited, 
so obscuring these objects may be feasible to hinder the attack.

I leverage randomize to puzzle the slab layout
(just replace `kmalloc` with `kmalloc_rand`).

1. **kmalloc cache randomize**: 
there are 13 kmalloc caches for each type, we can select other kmalloc 
caches whose slot size is larger than requested

2. **inner-slot randomize**: 
slub allocated equal or larger slot for current request to load the object, 
so take full use of the extra blank space,randomize the position of the 
object in the slot, and return the randomized address.

after deploying 2 features, attackers neither know which cache to spray, 
nor the accurate offset from the pointers in the slot(or between the slots).
No matter OOB, double-free, or UAF.


details:(and annotations in source code)
1. inner-slot only randomize caches whose slot size is the power of 2,
because slub de-randomize randomized objects' addresses by aligning the 
slot size, caches slot size  192 or 96 are hard to align.
2. allocated by `kmalloc_rand`,  free by `kfree` same as other objects.
3. the inner-slot randomize must be 8 bytes alignment, otherwise 'ALIGN CHECK' 
trap will be triggered
4. cache randomize and inner-slot randomize are separate features, enable one 
of them would also help.

drawbacks:
1. waste of memory
2. cannot randomize cache which size is 4K

TODO:
1. do some static analysis about victim and spray objects,
find them and test the randomize feature
2. test KASAN with randomizing feature.


Appendix: (statistic of extra space in slots)

sudo bpftrace -e 'tracepoint:kmem:kmalloc { @[args->bytes_alloc-args->bytes_req] = count();
  @padding=hist(args->bytes_alloc-args->bytes_req); }'

@padding: 
[0]               173774 |@@@@@@@@@@@                                         |
[1]               103149 |@@@@@@                                              |
[2, 4)             89517 |@@@@@@                                              |
[4, 8)            242056 |@@@@@@@@@@@@@@@@                                    |
[8, 16)           768225 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[16, 32)          649336 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@         |
[32, 64)           12109 |                                                    |
[64, 128)          11286 |                                                    |
[128, 256)          7576 |                                                    |
[256, 512)          9425 |                                                    |
[512, 1K)           6569 |                                                    |
[1K, 2K)            7271 |                                                    |
[2K, 4K)               5 |                                                    |
[4K, 8K)               1 |                                                    |

thanks.

Wang Zi-cheng
---
 include/linux/slab.h | 10 ++++++++
 mm/slub.c            | 55 ++++++++++++++++++++++++++++++++++++++++++++
 2 files changed, 65 insertions(+)

diff --git a/include/linux/slab.h b/include/linux/slab.h
index 083f3ce550bc..7d372f1f10b9 100644
--- a/include/linux/slab.h
+++ b/include/linux/slab.h
@@ -426,6 +426,7 @@ static __always_inline unsigned int __kmalloc_index(size_t size,
 #endif /* !CONFIG_SLOB */
 
 void *__kmalloc(size_t size, gfp_t flags) __assume_kmalloc_alignment __malloc;
+void *__kmalloc_rand(size_t size, gfp_t flags) __assume_kmalloc_alignment __malloc;
 void *kmem_cache_alloc(struct kmem_cache *, gfp_t flags) __assume_slab_alignment __malloc;
 void kmem_cache_free(struct kmem_cache *, void *);
 
@@ -596,6 +597,15 @@ static __always_inline void *kmalloc(size_t size, gfp_t flags)
 	return __kmalloc(size, flags);
 }
 
+
+static __always_inline void *kmalloc_rand(size_t size, gfp_t flags) 
+{
+	if (size > PAGE_SIZE)
+		return kmalloc(size, flags);
+	return __kmalloc_rand(size, flags);
+}
+
+
 static __always_inline void *kmalloc_node(size_t size, gfp_t flags, int node)
 {
 #ifndef CONFIG_SLOB
diff --git a/mm/slub.c b/mm/slub.c
index 2ee43ff667a5..e33b9747257e 100644
--- a/mm/slub.c
+++ b/mm/slub.c
@@ -4121,6 +4121,54 @@ void *__kmalloc(size_t size, gfp_t flags)
 }
 EXPORT_SYMBOL(__kmalloc);
 
+/*
+ * get random index between 2^3 to 2^ 12
+ * (8 bytes to 4096 bytes, index [3,12])
+ */
+unsigned int get_random_index(size_t size) 
+{
+	unsigned int index = fls(size - 1);
+	unsigned int diff = KMALLOC_SHIFT_HIGH - index - 1;
+
+	// if pick 4096 cache
+	if (!diff)
+		return index;
+	index = index + (get_random_int() % diff);
+
+	return index;
+}
+
+void *__kmalloc_rand(size_t size, gfp_t flags)
+{
+	struct kmem_cache *s;
+	void *ret;
+	unsigned long entropy = 0;
+	
+	// get a random cache, equal or larger than origin cache
+	s = kmalloc_caches[kmalloc_type(flags)][get_random_index(size)];
+
+	if (unlikely(ZERO_OR_NULL_PTR(s)))
+		return s;
+
+	ret = slab_alloc(s, flags, _RET_IP_, size);
+
+	trace_kmalloc(_RET_IP_, ret, size, s->size, flags);
+
+	// calculate inner-slot blank space
+	entropy = s->object_size - (unsigned long)size;
+	entropy = (get_random_long() % entropy);
+	/* get an inner-slot randomize ret address
+	 * 8 bytes align, intel check alignment for all pointers
+	 * see ALIGNMENT CHECK trap
+	 */
+	ret = ((unsigned long)ret + entropy) & 0xfffffffffffffff8;
+
+	/* haven't tested yet */
+	ret = kasan_kmalloc(s, ret, size, flags);
+	return ret;
+}
+EXPORT_SYMBOL(__kmalloc_rand);
+
 #ifdef CONFIG_NUMA
 static void *kmalloc_large_node(size_t size, gfp_t flags, int node)
 {
@@ -4256,6 +4304,7 @@ void kfree(const void *x)
 {
 	struct page *page;
 	void *object = (void *)x;
+	struct kmem_cache *s;
 
 	trace_kfree(_RET_IP_, x);
 
@@ -4263,6 +4312,7 @@ void kfree(const void *x)
 		return;
 
 	page = virt_to_head_page(x);
+
 	if (unlikely(!PageSlab(page))) {
 		unsigned int order = compound_order(page);
 
@@ -4273,6 +4323,11 @@ void kfree(const void *x)
 		__free_pages(page, order);
 		return;
 	}
+
+	s = page->slab_cache;
+	if (((s->object_size) & (s->object_size - 1)) == 0)
+		object = (void *) ((unsigned long) object & (0xffffffffffffffff - s->object_size + 1));
+
 	slab_free(page->slab_cache, page, object, NULL, 1, _RET_IP_);
 }
 EXPORT_SYMBOL(kfree);
-- 
2.32.0

