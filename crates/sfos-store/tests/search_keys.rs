//! Runs only when `TEST_DATABASE_URL` points at a throwaway Postgres.
use sfos_store::Store;

#[tokio::test]
async fn prepare_search_fills_dictionary_and_index() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let store = Store::connect(&url, 4).expect("connect");
    store.migrate().await.expect("migrate");
    let tenant = store
        .ensure_tenant("search-keys-test", "Search keys test")
        .await
        .expect("tenant");
    let c = store.pool().get().await.expect("client");
    c.execute(
        "DELETE FROM hourly_activity WHERE tenant_id = $1",
        &[&tenant.id],
    )
    .await
    .expect("clean");
    c.execute(
        "INSERT INTO hourly_activity (tenant_id, hour, dimension, key, events)
         VALUES ($1, date_trunc('hour', now()), 'users', 'alice', 5),
                ($1, date_trunc('hour', now()) - interval '2 hours', 'users', 'alice', 5),
                ($1, date_trunc('hour', now()), 'sites', 'example.org', 3),
                ($1, date_trunc('hour', now()), 'not_searchable', 'x', 1)",
        &[&tenant.id],
    )
    .await
    .expect("seed");
    c.execute("DELETE FROM search_keys", &[])
        .await
        .expect("reset dictionary");

    store.prepare_search().await.expect("prepare");
    store.prepare_search().await.expect("prepare is repeatable");

    let rows = c
        .query(
            "SELECT dimension, key FROM search_keys WHERE tenant_id = $1 ORDER BY 1, 2",
            &[&tenant.id],
        )
        .await
        .expect("dictionary");
    let got: Vec<(String, String)> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    assert_eq!(
        got,
        vec![
            ("sites".to_string(), "example.org".to_string()),
            ("users".to_string(), "alice".to_string())
        ]
    );
    let valid: bool = c
        .query_one(
            "SELECT i.indisvalid FROM pg_class c JOIN pg_index i ON i.indexrelid = c.oid
             WHERE c.relname = 'hourly_activity_key_idx'",
            &[],
        )
        .await
        .expect("index exists")
        .get(0);
    assert!(valid);
}
