package classify

import (
	"github.com/zysen1/Egress-Ledger/internal/capture"
	"github.com/zysen1/Egress-Ledger/internal/gitpack"
)

type gitObj = gitpack.Object

func gitpackTypeBlob() string { return gitpack.TypeBlob }

func gitObject(kind string, data []byte) gitpack.Object {
	return gitpack.Object{Type: kind, Data: data, Hash: gitpack.Hash(kind, data)}
}

func mustPack(objs []gitpack.Object) []byte {
	b, err := gitpack.Build(objs)
	if err != nil {
		panic(err)
	}
	return b
}

func fakeFlow(path, query, ct string, body []byte) capture.Flow {
	return capture.Flow{
		Path:        path,
		Query:       query,
		ContentType: ct,
		Body:        body,
		BodyBytes:   len(body),
	}
}
