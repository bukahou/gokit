package localauth_test

import (
	"testing"

	"github.com/bukahou/gokit/localauth"
	"github.com/bukahou/gokit/localauth/storetest"
)

// 内存实现是三个契约的【参考实现】: storetest 里的每条断言都必须先在它上面成立,
// 否则契约测试本身就是错的。宿主的真实存储再拿同一组断言去验。
//
// ⚠️ 内存 FailureStore 的键是逐字节比较的 (map), 所以这里调用的是 AssertKeysDistinct;
// 一个大小写不敏感的数据库实现应当改调 AssertKeysShareBucket。两者选哪个由宿主的
// 排序规则决定, 见 storetest 包注释。

func TestMemStore_满足FailureStore契约(t *testing.T) {
	storetest.RunFailureStoreTests(t, func(t *testing.T) localauth.FailureStore {
		return localauth.NewMemStore()
	})
	storetest.AssertKeysDistinct(t, localauth.NewMemStore(), "Alice", "alice")
}

func TestSessionMemStore_满足SessionStore契约(t *testing.T) {
	storetest.RunSessionStoreTests(t, func(t *testing.T) localauth.SessionStore {
		return localauth.NewSessionMemStore()
	})
}

func TestVerificationMemStore_满足VerificationStore契约(t *testing.T) {
	storetest.RunVerificationStoreTests(t, func(t *testing.T) localauth.VerificationStore {
		return localauth.NewVerificationMemStore()
	})
}
