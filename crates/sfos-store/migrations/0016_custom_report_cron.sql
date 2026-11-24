-- Custom (on-demand) reports have no schedule, so their cron expression is empty. The original
-- constraint rejected the empty string, which made every "save custom report" fail with HTTP 500.
ALTER TABLE report_schedules DROP CONSTRAINT IF EXISTS report_schedules_cron_schedule_check;
ALTER TABLE report_schedules ADD CONSTRAINT report_schedules_cron_schedule_check
    CHECK (report_type = 'custom' OR cron_schedule <> '');
