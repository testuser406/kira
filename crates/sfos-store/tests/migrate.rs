//! Database integration test. Runs only when `TEST_DATABASE_URL` points at a
//! throwaway Postgres (CI provides one); otherwise it is skipped.
use sfos_store::Store;

#[tokio::test]
async fn migrations_apply_twice_and_seed_templates() {
    let Ok(url) = std::env::var("TEST_DATABASE_URL") else {
        eprintln!("TEST_DATABASE_URL not set; skipping");
        return;
    };
    let store = Store::connect(&url, 4).expect("connect");
    store.migrate().await.expect("first migrate");
    store.migrate().await.expect("second migrate is a no-op");
    let tenant = store
        .ensure_tenant("default", "Test")
        .await
        .expect("tenant");
    store
        .ensure_tenant("default", "Test")
        .await
        .expect("idempotent");
    let templates = store
        .list_report_templates(tenant.id)
        .await
        .expect("templates");
    assert_eq!(templates.len(), 17, "4 original + 13 report-type templates");
}
