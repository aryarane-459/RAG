
def reciprocal_rank_fusion(
    vector_results,
    bm25_results,
    k=60,
    top_k=10
):

    fused_scores = {}
    chunks_by_id = {}

    for rank, chunk in enumerate(vector_results, start=1):

        chunk_id = int(chunk["chunk_id"])

        fused_scores[chunk_id] = (
            fused_scores.get(chunk_id, 0)
            + 1 / (k + rank)
        )

        chunks_by_id[chunk_id] = chunk

    for rank, chunk in enumerate(bm25_results, start=1):

        chunk_id = int(chunk["chunk_id"])

        fused_scores[chunk_id] = (
            fused_scores.get(chunk_id, 0)
            + 1 / (k + rank)
        )

        if chunk_id not in chunks_by_id:
            chunks_by_id[chunk_id] = chunk

    ranked_chunk_ids = sorted(
        fused_scores,
        key=lambda chunk_id: fused_scores[chunk_id],
        reverse=True
    )

    final_results = []

    for chunk_id in ranked_chunk_ids[:top_k]:

        chunk = chunks_by_id[chunk_id].copy()

        chunk["rrf_score"] = fused_scores[chunk_id]

        final_results.append(chunk)

    return final_results
