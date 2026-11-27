-- Allow Excel (xlsx) as a scheduled-report and share-link format.
ALTER TABLE report_schedules DROP CONSTRAINT IF EXISTS report_schedules_format_check;
ALTER TABLE report_schedules ADD CONSTRAINT report_schedules_format_check CHECK (format IN ('csv', 'pdf', 'xlsx'));
ALTER TABLE report_shares DROP CONSTRAINT IF EXISTS report_shares_format_check;
ALTER TABLE report_shares ADD CONSTRAINT report_shares_format_check CHECK (format IN ('pdf', 'csv', 'xlsx'));
