-- AttackGen command pool schema.
--
-- Stores simulated process-command telemetry rows. Every value is inert text;
-- nothing in this project executes a command_line. The composer reads from this
-- table by label, category and os_profile (with optional scenario_tags).

CREATE TABLE IF NOT EXISTS command_lines (
    id            BIGSERIAL PRIMARY KEY,
    process_name  TEXT       NOT NULL,
    command_line  TEXT       NOT NULL,
    label         TEXT       NOT NULL CHECK (label IN ('benign', 'malicious')),
    category      TEXT       NOT NULL,
    os_profile    TEXT       NOT NULL,
    scenario_tags TEXT[]     NOT NULL DEFAULT '{}',
    stealth_level INTEGER,
    weight        DOUBLE PRECISION DEFAULT 1.0
);

-- The composer filters heavily on these three columns; index the common path.
CREATE INDEX IF NOT EXISTS idx_command_lines_label_category_os
    ON command_lines (label, category, os_profile);

-- GIN index supports the optional scenario_tags overlap (&&) filter.
CREATE INDEX IF NOT EXISTS idx_command_lines_scenario_tags
    ON command_lines USING GIN (scenario_tags);
