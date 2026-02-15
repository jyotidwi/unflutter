package main

import (
	"unflutter/internal/cluster"
	"unflutter/internal/pipeline"
	"unflutter/internal/snapshot"
)

type poolLookups = pipeline.PoolLookups
func buildPoolLookups(result *cluster.Result, ct *snapshot.CIDTable, vmResult *cluster.Result) *poolLookups {
	return pipeline.BuildPoolLookups(result, ct, vmResult)
}

func resolvePoolDisplay(pool []cluster.PoolEntry, l *poolLookups) map[int]string {
	return pipeline.ResolvePoolDisplay(pool, l)
}
