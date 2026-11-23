-- Add report_subtype column to report_schedules for custom report categorization
ALTER TABLE report_schedules ADD COLUMN IF NOT EXISTS report_subtype text;
COMMENT ON COLUMN report_schedules.report_subtype IS 'Subtype for custom reports (e.g., user_activity, security, bandwidth, etc.)';

-- Add index for filtering by report_subtype
CREATE INDEX IF NOT EXISTS report_schedules_report_subtype_idx ON report_schedules (report_subtype);