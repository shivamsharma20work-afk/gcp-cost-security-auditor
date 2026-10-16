-- Handy BigQuery queries over audit.findings

-- 1. Today's findings, worst first
SELECT severity, check, resource, location, detail, est_monthly_cost_usd
FROM `audit.findings`
WHERE DATE(scanned_at, "Asia/Kolkata") = CURRENT_DATE("Asia/Kolkata")
ORDER BY CASE severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END;

-- 2. Estimated monthly waste per project, last 30 days (latest scan per day)
SELECT project, DATE(scanned_at) AS day, ROUND(SUM(est_monthly_cost_usd), 2) AS waste_usd
FROM `audit.findings`
WHERE scanned_at > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
GROUP BY project, day
ORDER BY day;

-- 3. Resources flagged 7+ days in a row (nobody is fixing these)
SELECT project, check, resource, COUNT(DISTINCT DATE(scanned_at)) AS days_flagged
FROM `audit.findings`
WHERE scanned_at > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY project, check, resource
HAVING days_flagged >= 7;
