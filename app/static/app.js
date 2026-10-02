"use strict";


/* =========================================================
   SENTINEL DASHBOARD
   Frontend Controller
========================================================= */

const $ = id => document.getElementById(id);

const isObject = value => (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value)
);

const list = value => (
    Array.isArray(value) ? value : []
);

const objects = value => (
    list(value).filter(isObject)
);

const text = value => (
    value == null ? "" : String(value)
);


/* =========================================================
   CONSTANTS
========================================================= */

const riskOrder = {
    High: 0,
    Medium: 1,
    Low: 2,
    Informational: 3,
};


const inputLabels = {
    RAW_MARKUP_REFLECTED:
        "Raw markup reflected",

    HTML_ENCODED_MARKUP_REFLECTED:
        "Encoded markup reflected",

    NO_REFLECTION_OBSERVED:
        "No reflection observed",

    MARKER_REFLECTED_WITH_TRANSFORMATION:
        "Transformed marker reflected",

    MARKUP_NOT_REFLECTED:
        "Markup not reflected",

    MARKUP_RESPONSE_NOT_ASSESSABLE:
        "Inconclusive: markup response",

    MARKER_RESPONSE_NOT_ASSESSABLE:
        "Inconclusive: marker response",

    BASELINE_NOT_ASSESSABLE:
        "Inconclusive: baseline response",

    MARKER_COLLISION:
        "Inconclusive: marker collision",

    CHECK_ERROR:
        "Check error",

    SKIPPED_CANDIDATE_LIMIT:
        "Skipped: candidate limit",

    SKIPPED_TIME_LIMIT:
        "Skipped: time limit",

    NOT_PLANNED:
        "Not planned by generic query stage",

    NOT_REPORTED:
        "Reflection result not reported",

    OPEN_REDIRECT_CONFIRMED:
        "Specialized check: open redirect confirmed",

    EXTERNAL_REDIRECT_BLOCKED:
        "Specialized check: external redirect blocked",
};


/* =========================================================
   STATE
========================================================= */

let report = null;
let running = false;
let timer = null;
let renderedJob = null;
let pollingVersion = 0;


/* =========================================================
   DOM HELPERS
========================================================= */

function element(
    tag,
    value = "",
    className = "",
) {
    const node = document.createElement(tag);

    node.textContent = text(value);

    if (className) {
        node.className = className;
    }

    return node;
}


function replaceText(id, value) {
    const node = $(id);

    if (node) {
        node.textContent = text(value);
    }
}


function setBusy(value) {
    running = value;

    for (const id of [
        "target",
        "start",
        "file",
    ]) {
        const node = $(id);

        if (node) {
            node.disabled = value;
        }
    }

    $("busy").hidden = !value;
}


/* =========================================================
   FINDING GROUPING
========================================================= */

function findingKey(alert) {
    return JSON.stringify([
        alert.rule_id || alert.pluginId || "",
        alert.alert || "",
        alert.risk || "",
    ]);
}


function groupFindings(alerts) {
    const groups = new Map();

    for (const alert of alerts) {
        if (!isObject(alert)) {
            continue;
        }

        const key = findingKey(alert);

        if (!groups.has(key)) {
            groups.set(
                key,
                {
                    sample: alert,
                    records: [],
                    urls: new Set(),
                },
            );
        }

        const group = groups.get(key);

        group.records.push(alert);

        if (alert.url) {
            group.urls.add(alert.url);
        }
    }

    return [...groups.values()].sort(
        (first, second) => (
            (riskOrder[first.sample.risk] ?? 99) -
            (riskOrder[second.sample.risk] ?? 99)
        ),
    );
}


/* =========================================================
   FORM GROUPING
========================================================= */

function groupForms(forms) {
    const groups = new Map();

    for (const form of objects(forms)) {
        const fields = objects(form.fields).map(
            field => ({
                name: text(field.name),
                type: text(field.type),
            }),
        );

        fields.sort(
            (first, second) => (
                JSON.stringify(first).localeCompare(
                    JSON.stringify(second),
                )
            ),
        );

        let action = text(form.action);

        try {
            action = new URL(
                action,
                form.page || report?.target,
            ).href;
        } catch {
            // Keep the original action.
        }

        const method = text(
            form.method || "GET",
        ).toUpperCase();

        const key = JSON.stringify([
            action,
            method,
            fields,
        ]);

        if (!groups.has(key)) {
            groups.set(
                key,
                {
                    action,
                    method,
                    fields,
                    occurrences: 0,
                    pages: new Set(),
                },
            );
        }

        const group = groups.get(key);

        group.occurrences += 1;

        if (form.page) {
            group.pages.add(
                text(form.page),
            );
        }
    }

    return [...groups.values()].map(
        group => ({
            action: group.action,
            method: group.method,
            fields: group.fields,
            occurrences: group.occurrences,
            observed_on_pages: [...group.pages],
        }),
    );
}


/* =========================================================
   COVERAGE
========================================================= */

function stageDescription(
    key,
    label,
    stage,
) {
    if (!isObject(stage)) {
        return null;
    }

    if (
        ![
            "incomplete",
            "limited",
            "skipped",
        ].includes(stage.status)
    ) {
        return null;
    }

    if (stage.status === "skipped") {
        return (
            `${label} skipped: ` +
            `${stage.reason || "Reason not provided"}`
        );
    }

    if (key === "reflection") {
        return (
            `${label}: ` +
            `${stage.completed_candidates ?? "Unknown"}/` +
            `${stage.candidate_count ?? "Unknown"} ` +
            "candidates completed; " +
            `${stage.inconclusive_or_skipped ?? "Unknown"} ` +
            "inconclusive or skipped"
        );
    }

    const completed = stage.completed_routes;
    const total = stage.candidate_routes;

    if (
        completed != null &&
        total != null
    ) {
        return (
            `${label}: ` +
            `${completed}/${total} routes completed`
        );
    }

    return `${label}: ${stage.status}`;
}


function coverageSummary(value) {
    const coverage = value.coverage;

    if (!isObject(coverage)) {
        return (
            "Coverage metadata is not available " +
            "in this report."
        );
    }

    const limitations = [];

    if (
        Number(coverage.remaining_queued_urls) > 0
    ) {
        limitations.push(
            `${coverage.remaining_queued_urls} ` +
            "discovered URLs remain queued",
        );
    }

    if (coverage.discovery_limit_reached) {
        limitations.push(
            "The URL discovery limit was reached",
        );
    }

    const errors = list(value.errors);

    if (errors.length) {
        limitations.push(
            `${errors.length} assessment error ` +
            "record(s) were reported",
        );
    }

    if (
        coverage.html_pages_assessed === 0
    ) {
        limitations.push(
            "No HTML page was successfully assessed",
        );
    }

    const stages = [
        [
            "browser_xss",
            "Browser XSS",
        ],
        [
            "sql_injection",
            "SQL injection",
        ],
        [
            "open_redirect",
            "Open redirect",
        ],
        [
            "cors",
            "CORS",
        ],
        [
            "reflection",
            "Query reflection",
        ],
        [
            "input_inventory",
            "Input inventory",
        ],
        [
            "request_planning",
            "Request planning",
        ],
    ];

    for (
        const [key, label]
        of stages
    ) {
        const result = stageDescription(
            key,
            label,
            coverage[key],
        );

        if (result) {
            limitations.push(result);
        }
    }

    if (
        value.assessment_status === "incomplete" &&
        !limitations.length
    ) {
        limitations.push(
            "The report is incomplete, but no " +
            "specific limitation was recorded",
        );
    }

    const notTested = list(
        coverage.not_tested,
    );

    const parts = [
        `Assessment status: ${
            value.assessment_status ||
            "Not provided"
        }.`,

        `HTML pages assessed: ${
            coverage.html_pages_assessed ??
            "Unknown"
        }.`,

        `URLs discovered: ${
            coverage.urls_discovered ??
            "Unknown"
        }.`,
    ];

    if (limitations.length) {
        parts.push(
            `Coverage limitations: ${
                limitations.join("; ")
            }.`,
        );
    } else {
        parts.push(
            "No execution limitation was recorded " +
            "within the reported scope.",
        );
    }

    if (notTested.length) {
        parts.push(
            `Not tested: ${
                notTested.join(", ")
            }.`,
        );
    }

    parts.push(
        "Coverage applies only to the reported " +
        "assessment scope.",
    );

    return parts.join(" ");
}


/* =========================================================
   REPORT VALIDATION
========================================================= */

function validateReport(value) {
    if (
        !isObject(value) ||
        !Array.isArray(value.alerts)
    ) {
        throw new Error(
            "The selected file is not a supported report.",
        );
    }

    for (const alert of value.alerts) {
        if (!isObject(alert)) {
            throw new Error(
                "Invalid finding record.",
            );
        }

        for (const key of [
            "risk",
            "alert",
            "url",
            "param",
        ]) {
            if (
                alert[key] != null &&
                typeof alert[key] !== "string"
            ) {
                throw new Error(
                    `Invalid finding field: ${key}`,
                );
            }
        }
    }

    const listFields = [
        "pages",
        "forms",
        "errors",
        "input_inventory",
        "reflection_checks",
        "xss_checks",
        "sqli_checks",
        "open_redirect_checks",
        "cors_checks",
    ];

    for (const key of listFields) {
        if (
            value[key] != null &&
            !Array.isArray(value[key])
        ) {
            throw new Error(
                `The report field "${key}" must be a list.`,
            );
        }
    }

    if (value.request_plan != null) {
        if (!isObject(value.request_plan)) {
            throw new Error(
                "The request plan must be an object.",
            );
        }

        for (const key of [
            "candidates",
            "skipped_inputs",
        ]) {
            if (
                value.request_plan[key] != null &&
                !Array.isArray(
                    value.request_plan[key],
                )
            ) {
                throw new Error(
                    `The request-plan field "${key}" ` +
                    "must be a list.",
                );
            }
        }
    }
}


/* =========================================================
   SUMMARY
========================================================= */

function addStat(
    label,
    value,
) {
    const block = document.createElement("div");

    block.className = "stat";

    block.append(
        element(
            "strong",
            value,
        ),
        element(
            "span",
            label,
        ),
    );

    $("summary").append(block);
}


function renderSummary(value) {
    const alerts = list(value.alerts);

    const groups = groupFindings(
        alerts,
    );

    const formGroups = groupForms(
        value.forms,
    );

    $("summary").replaceChildren();

    addStat(
        "Finding records",
        alerts.length,
    );

    addStat(
        "Finding groups",
        groups.length,
    );

    for (
        const risk
        of Object.keys(riskOrder)
    ) {
        addStat(
            `${risk} records`,
            alerts.filter(
                alert => alert.risk === risk,
            ).length,
        );
    }

    addStat(
        "Pages",
        list(value.pages).length,
    );

    addStat(
        "Inputs",
        list(value.input_inventory).length,
    );

    addStat(
        "Form patterns",
        formGroups.length,
    );
}


/* =========================================================
   REPORT DISPLAY
========================================================= */

function showReport(value) {
    validateReport(value);

    report = value;

    const formGroups = groupForms(
        value.forms,
    );

    replaceText(
        "report-target",
        value.target
            ? `Report target: ${value.target}`
            : "Report target: Not provided",
    );

    replaceText(
        "coverage",
        coverageSummary(value),
    );

    renderSummary(value);

    $("inventory").textContent = JSON.stringify(
        {
            report_target:
                value.target || null,

            assessment_status:
                value.assessment_status || null,

            grouping_note: (
                "Forms are grouped by action, method, " +
                "and field names/types. Matching patterns " +
                "do not prove identical behavior."
            ),

            pages:
                list(value.pages),

            form_patterns:
                formGroups,

            errors:
                list(value.errors),
        },
        null,
        2,
    );

    renderRows();
    renderInputRows();
}


/* =========================================================
   BUTTON HELPERS
========================================================= */

function detailButton(
    label,
    handler,
) {
    const button = element(
        "button",
        label,
        "secondary",
    );

    button.type = "button";
    button.onclick = handler;

    return button;
}


/* =========================================================
   FINDINGS TABLE
========================================================= */

function createRiskCell(risk) {
    const cell = document.createElement("td");

    const riskClass =
        Object.prototype.hasOwnProperty.call(
            riskOrder,
            risk,
        )
            ? risk.toLowerCase()
            : "informational";

    const badge = element(
        "span",
        risk || "Unknown",
        riskClass,
    );

    cell.append(badge);

    return cell;
}


function renderRows() {
    $("rows").replaceChildren();

    const alerts = list(
        report?.alerts,
    );

    const selectedRisk =
        $("risk").value;

    const query =
        $("search")
            .value
            .trim()
            .toLowerCase();

    const matching = alerts.filter(
        alert => {
            const riskMatches = (
                selectedRisk === "All" ||
                alert.risk === selectedRisk
            );

            const searchText = [
                alert.alert,
                alert.url,
                alert.param,
                alert.rule_id,
                alert.category,
                alert.confidence,
            ]
                .map(text)
                .join(" ")
                .toLowerCase();

            return (
                riskMatches &&
                searchText.includes(query)
            );
        },
    );

    const groups = groupFindings(
        matching,
    );

    for (const group of groups) {
        const row =
            document.createElement("tr");

        const risk =
            group.sample.risk ||
            "Not provided";

        const findingCell =
            document.createElement("td");

        const findingName = element(
            "div",
            group.sample.alert ||
            "Unnamed finding",
        );

        const findingMeta = element(
            "small",
            (
                `${group.records.length} record(s) · ` +
                `${group.urls.size} URL(s)`
            ),
        );

        findingMeta.style.display = "block";
        findingMeta.style.marginTop = "5px";
        findingMeta.style.color = "#536b82";

        findingCell.append(
            findingName,
            findingMeta,
        );

        const urls = [
            ...group.urls,
        ];

        const urlText = (
            urls[0] ||
            "Not provided"
        ) + (
            urls.length > 1
                ? ` (+${urls.length - 1} more)`
                : ""
        );

        const actionCell =
            document.createElement("td");

        actionCell.append(
            detailButton(
                "View Details",
                () => showGroupDetails(group),
            ),
        );

        row.append(
            createRiskCell(risk),
            findingCell,
            element(
                "td",
                urlText,
                "url",
            ),
            actionCell,
        );

        $("rows").append(row);
    }

    const allGroups =
        groupFindings(alerts);

    replaceText(
        "count",
        (
            `Showing ${groups.length} of ` +
            `${allGroups.length} finding groups · ` +
            `${matching.length} of ` +
            `${alerts.length} finding records.`
        ),
    );
}


/* =========================================================
   SPECIALIZED INPUT RESULTS
========================================================= */

function findRedirectResult(
    skipped,
) {
    const checks = objects(
        report?.open_redirect_checks,
    );

    return checks.find(
        check => (
            text(check.url) ===
                text(skipped.page) &&
            text(check.parameter) ===
                text(skipped.parameter)
        ),
    ) || null;
}


/* =========================================================
   INPUT ENTRIES
========================================================= */

function inputEntries() {
    if (!report) {
        return [];
    }

    const plan = isObject(
        report.request_plan,
    )
        ? report.request_plan
        : {};

    const checks = objects(
        report.reflection_checks,
    );

    const seen =
        new Set();

    const entries = [];


    /* -----------------------------------------------------
       Planned query candidates
    ----------------------------------------------------- */

    for (
        const candidate
        of objects(plan.candidates)
    ) {
        const matches = checks.filter(
            check => (
                check.candidate_id ===
                candidate.candidate_id
            ),
        );

        const results =
            matches.length
                ? matches
                : [null];

        for (const check of results) {
            if (check) {
                seen.add(check);
            }

            entries.push({
                candidate,
                check,

                id:
                    text(
                        candidate.candidate_id,
                    ),

                sourceIds:
                    list(
                        candidate.source_input_ids,
                    ),

                url:
                    text(
                        check?.url ||
                        candidate.original_url,
                    ),

                parameter:
                    text(
                        check?.parameter ||
                        candidate.parameter,
                    ),

                status:
                    check?.classification ||
                    "NOT_REPORTED",

                stage:
                    "reflection",
            });
        }
    }


    /* -----------------------------------------------------
       Preserve standalone reflection records
    ----------------------------------------------------- */

    for (const check of checks) {
        if (seen.has(check)) {
            continue;
        }

        entries.push({
            check,

            id:
                text(
                    check.candidate_id,
                ),

            sourceIds:
                list(
                    check.source_input_ids,
                ),

            url:
                text(check.url),

            parameter:
                text(check.parameter),

            status:
                check.classification ||
                "NOT_REPORTED",

            stage:
                "reflection",
        });
    }


    /* -----------------------------------------------------
       Generic planner exclusions
    ----------------------------------------------------- */

    for (
        const skipped
        of objects(plan.skipped_inputs)
    ) {
        const redirectResult =
            findRedirectResult(skipped);

        entries.push({
            skipped,

            specializedCheck:
                redirectResult,

            id:
                text(
                    skipped.input_id,
                ),

            sourceIds:
                skipped.input_id
                    ? [skipped.input_id]
                    : [],

            url:
                text(skipped.page),

            parameter:
                text(
                    skipped.parameter,
                ),

            status:
                redirectResult?.classification ||
                "NOT_PLANNED",

            stage:
                redirectResult
                    ? "open_redirect"
                    : "planning",
        });
    }

    return entries;
}


/* =========================================================
   INPUT TABLE
========================================================= */

function renderInputRows() {
    $("input-rows").replaceChildren();

    const entries =
        inputEntries();

    const query =
        $("input-search")
            .value
            .trim()
            .toLowerCase();

    const matching = entries.filter(
        entry => {
            const searchText = [
                entry.id,
                ...entry.sourceIds,
                entry.url,
                entry.parameter,
                entry.status,
                inputLabels[
                    entry.status
                ],
                entry.stage,
                entry.skipped?.reason,
            ]
                .map(text)
                .join(" ")
                .toLowerCase();

            return searchText.includes(
                query,
            );
        },
    );

    for (const entry of matching) {
        const row =
            document.createElement("tr");

        const action =
            document.createElement("td");

        action.append(
            detailButton(
                "View Check",
                () => showInputDetails(
                    entry,
                ),
            ),
        );

        row.append(
            element(
                "td",
                entry.id ||
                "Not provided",
            ),

            element(
                "td",
                entry.url ||
                "Not provided",
                "url",
            ),

            element(
                "td",
                entry.parameter ||
                "Not provided",
            ),

            element(
                "td",
                inputLabels[
                    entry.status
                ] ||
                entry.status,
            ),

            action,
        );

        $("input-rows").append(row);
    }

    if (!report) {
        replaceText(
            "input-count",
            "No report loaded.",
        );

        return;
    }

    if (
        !isObject(
            report.request_plan,
        ) &&
        !Array.isArray(
            report.reflection_checks,
        )
    ) {
        replaceText(
            "input-count",
            (
                "This report does not contain " +
                "input-planning or reflection data."
            ),
        );

        return;
    }

    const genericExcluded =
        entries.filter(
            entry => (
                entry.status ===
                "NOT_PLANNED"
            ),
        ).length;

    const specialized =
        entries.filter(
            entry => (
                entry.stage ===
                "open_redirect"
            ),
        ).length;

    replaceText(
        "input-count",
        (
            `Showing ${matching.length} of ` +
            `${entries.length} input-check records. ` +
            `${genericExcluded} input(s) were excluded ` +
            "from generic planning. " +
            `${specialized} excluded input(s) received ` +
            "a specialized redirect check."
        ),
    );
}


/* =========================================================
   DETAILS DIALOG
========================================================= */

function beginDetails(title) {
    replaceText(
        "detail-title",
        title,
    );

    $("detail-body")
        .replaceChildren();
}


function openDetails() {
    const dialog =
        $("details");

    if (!dialog.open) {
        dialog.showModal();
    }

    $("detail-body").scrollTop = 0;
}


function addDetail(
    label,
    value,
) {
    const content = (
        typeof value === "object" &&
        value !== null
    )
        ? JSON.stringify(
            value,
            null,
            2,
        )
        : text(value);

    $("detail-body").append(
        element(
            "h3",
            label,
        ),

        element(
            "pre",
            content ||
            "Not provided",
        ),
    );
}


function uniqueText(
    records,
    key,
) {
    return [
        ...new Set(
            records
                .map(
                    record =>
                        text(record[key]),
                )
                .filter(Boolean),
        ),
    ].join("\n\n");
}


/* =========================================================
   FINDING DETAILS
========================================================= */

function showGroupDetails(group) {
    beginDetails(
        "Finding Details",
    );

    addDetail(
        "Finding",
        group.sample.alert,
    );

    addDetail(
        "Risk",
        group.sample.risk,
    );

    addDetail(
        "Matching records",
        group.records.length,
    );

    addDetail(
        "Affected URLs",
        [...group.urls].join("\n"),
    );

    addDetail(
        "Grouping rule",
        (
            "Records share the same rule identifier, " +
            "finding title, and risk level. Grouping " +
            "does not prove a shared root cause."
        ),
    );

    for (
        const [key, label]
        of [
            [
                "confidence",
                "Reported confidence",
            ],
            [
                "category",
                "Category",
            ],
            [
                "description",
                "Description",
            ],
            [
                "solution",
                "Recommended actions",
            ],
            [
                "reference",
                "References",
            ],
        ]
    ) {
        const value =
            uniqueText(
                group.records,
                key,
            );

        if (value) {
            addDetail(
                label,
                value,
            );
        }
    }

    addDetail(
        "Evidence by record",
        group.records.map(
            (
                record,
                index,
            ) => ({
                record:
                    index + 1,

                url:
                    record.url,

                method:
                    record.method,

                parameter:
                    record.param,

                confidence:
                    record.confidence,

                evidence:
                    record.evidence,

                test_input:
                    record.attack,

                verification:
                    record.verification,
            }),
        ),
    );

    openDetails();
}


/* =========================================================
   INPUT DETAILS
========================================================= */

function showInputDetails(entry) {
    beginDetails(
        "Input Check Details",
    );

    addDetail(
        "Input or candidate ID",
        entry.id,
    );

    addDetail(
        "Source input IDs",
        entry.sourceIds,
    );

    addDetail(
        "URL",
        entry.url,
    );

    addDetail(
        "Parameter",
        entry.parameter,
    );

    addDetail(
        "Assessment stage",
        entry.stage,
    );

    addDetail(
        "Status",
        inputLabels[
            entry.status
        ] ||
        entry.status,
    );

    addDetail(
        "Classification code",
        entry.status,
    );


    /* -----------------------------------------------------
       Specialized redirect result
    ----------------------------------------------------- */

    if (entry.specializedCheck) {
        addDetail(
            "Generic planning result",
            entry.skipped?.reason ||
            "Not planned by the generic query stage.",
        );

        addDetail(
            "Specialized redirect verification",
            entry.specializedCheck,
        );

        addDetail(
            "Interpretation",
            (
                "The generic query planner excluded this " +
                "input because its source response was not " +
                "HTTP 200. A dedicated open-redirect stage " +
                "assessed the route separately."
            ),
        );
    }


    /* -----------------------------------------------------
       Generic exclusion
    ----------------------------------------------------- */

    else if (entry.skipped) {
        addDetail(
            "Reason not planned",
            entry.skipped.reason,
        );

        addDetail(
            "Interpretation",
            (
                "This status refers only to the generic " +
                "query-planning stage and must not be " +
                "interpreted as proof that the entire " +
                "route was not assessed."
            ),
        );
    }


    /* -----------------------------------------------------
       Reflection result
    ----------------------------------------------------- */

    else if (entry.check) {
        addDetail(
            "Interpretation",
            (
                "This is an HTTP reflection observation. " +
                "Raw markup reflection is not proof of " +
                "JavaScript execution. Encoded output or " +
                "absent reflection does not establish safety " +
                "in every execution context."
            ),
        );

        addDetail(
            "Evidence",
            entry.check.evidence,
        );

        addDetail(
            "Request observations",
            entry.check.observations,
        );

        if (entry.check.error) {
            addDetail(
                "Error",
                entry.check.error,
            );
        }

        addDetail(
            "JavaScript execution tested by this check",
            (
                entry.check
                    .javascript_execution_tested ==
                null
            )
                ? "Not reported"
                : entry.check
                    .javascript_execution_tested,
        );
    }


    /* -----------------------------------------------------
       Planned but no matching result
    ----------------------------------------------------- */

    else {
        addDetail(
            "Result",
            (
                "A request was planned, but the report " +
                "contains no matching reflection result. " +
                "This must not be interpreted as a " +
                "negative vulnerability result."
            ),
        );
    }


    if (entry.candidate) {
        addDetail(
            "Request plan",
            entry.candidate,
        );
    }

    const sources = objects(
        report?.input_inventory,
    ).filter(
        record => (
            entry.sourceIds.includes(
                record.input_id,
            )
        ),
    );

    if (sources.length) {
        addDetail(
            "Source observations",
            sources,
        );
    }

    openDetails();
}


/* =========================================================
   API
========================================================= */

async function api(
    url,
    options = {},
) {
    const response = await fetch(
        url,
        {
            ...options,
            cache: "no-store",
        },
    );

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(
            `Unexpected server response (${response.status}).`,
        );
    }

    if (!response.ok) {
        throw new Error(
            data.error ||
            "The request failed.",
        );
    }

    return data;
}


/* =========================================================
   POLLING
========================================================= */

function stopPolling() {
    if (timer !== null) {
        clearTimeout(timer);
        timer = null;
    }

    pollingVersion += 1;
}


function startPolling() {
    stopPolling();

    const version =
        pollingVersion;

    poll(version);
}


async function poll(version) {
    if (
        version !== pollingVersion
    ) {
        return;
    }

    try {
        const state =
            await api("/api/scan");

        if (
            version !== pollingVersion
        ) {
            return;
        }

        if (
            state.status === "idle"
        ) {
            setBusy(false);

            replaceText(
                "status",
                "Ready",
            );

            return;
        }

        setBusy(
            state.status === "running",
        );

        const messages =
            list(state.messages);

        $("log").textContent = (
            messages.join("\n") ||
            "Waiting for assessment messages..."
        );

        $("log").scrollTop =
            $("log").scrollHeight;


        /* -------------------------------------------------
           Running
        -------------------------------------------------- */

        if (
            state.status === "running"
        ) {
            replaceText(
                "status",
                (
                    "Assessment in progress: " +
                    `${state.target}`
                ),
            );

            timer = setTimeout(
                () => poll(version),
                1200,
            );

            return;
        }


        /* -------------------------------------------------
           Completed
        -------------------------------------------------- */

        if (
            state.status === "completed"
        ) {
            if (
                renderedJob !== state.id
            ) {
                showReport(
                    state.report,
                );

                renderedJob =
                    state.id;
            }

            replaceText(
                "status",
                (
                    "Assessment completed. " +
                    "Review findings, evidence, and " +
                    "coverage limitations below."
                ),
            );

            $("download").href =
                `/api/report/${
                    encodeURIComponent(
                        state.id,
                    )
                }`;

            $("download").hidden =
                false;

            return;
        }


        /* -------------------------------------------------
           Failed
        -------------------------------------------------- */

        replaceText(
            "status",
            (
                "Assessment failed: " +
                `${
                    state.error ||
                    "Unknown error"
                }`
            ),
        );

    } catch (error) {
        if (
            version !== pollingVersion
        ) {
            return;
        }

        replaceText(
            "status",
            (
                "Could not retrieve status. " +
                `Retrying... ${error.message}`
            ),
        );

        timer = setTimeout(
            () => poll(version),
            3000,
        );
    }
}


/* =========================================================
   UI RESET
========================================================= */

function resetDashboardForScan() {
    report = null;
    renderedJob = null;

    $("risk").value = "All";
    $("search").value = "";
    $("input-search").value = "";

    $("rows").replaceChildren();
    $("summary").replaceChildren();
    $("input-rows").replaceChildren();

    replaceText(
        "input-count",
        "Waiting for input checks.",
    );

    replaceText(
        "coverage",
        "",
    );

    replaceText(
        "report-target",
        "Waiting for the new report.",
    );

    replaceText(
        "inventory",
        "Discovery in progress.",
    );

    replaceText(
        "count",
        "Waiting for results.",
    );

    replaceText(
        "log",
        "Assessment started.",
    );

    $("download").hidden = true;

    if ($("details").open) {
        $("details").close();
    }
}


/* =========================================================
   START SCAN
========================================================= */

$("scan-form").addEventListener(
    "submit",
    async event => {
        event.preventDefault();

        if (running) {
            return;
        }

        stopPolling();
        setBusy(true);

        replaceText(
            "status",
            "Starting assessment engine...",
        );

        $("download").hidden = true;

        try {
            await api(
                "/api/scan",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json",

                        "X-CSRF-Token":
                            document.querySelector(
                                'meta[name="csrf-token"]',
                            ).content,
                    },

                    body:
                        JSON.stringify({
                            target:
                                $("target").value,
                        }),
                },
            );

            resetDashboardForScan();

            startPolling();

        } catch (error) {
            setBusy(false);

            replaceText(
                "status",
                error.message,
            );

            const version =
                pollingVersion;

            timer = setTimeout(
                () => poll(version),
                3000,
            );
        }
    },
);


/* =========================================================
   LOAD LOCAL JSON REPORT
========================================================= */

$("file").addEventListener(
    "change",
    async event => {
        const file =
            event.target.files[0];

        if (
            !file ||
            running
        ) {
            return;
        }

        stopPolling();

        const version =
            pollingVersion;

        try {
            if (
                file.size >
                10 * 1024 * 1024
            ) {
                throw new Error(
                    "The maximum report size is 10 MB.",
                );
            }

            const content =
                await file.text();

            if (
                version !== pollingVersion ||
                running
            ) {
                return;
            }

            const parsed =
                JSON.parse(content);

            showReport(parsed);

            $("risk").value = "All";
            $("search").value = "";
            $("input-search").value = "";

            renderRows();
            renderInputRows();

            if ($("details").open) {
                $("details").close();
            }

            $("download").hidden = true;

            replaceText(
                "status",
                `Report loaded: ${file.name}.`,
            );

            replaceText(
                "log",
                (
                    "A saved JSON report was opened locally. " +
                    "No new assessment was started."
                ),
            );

        } catch (error) {
            if (
                version === pollingVersion
            ) {
                replaceText(
                    "status",
                    error.message,
                );
            }
        } finally {
            event.target.value = "";
        }
    },
);


/* =========================================================
   FILTER EVENTS
========================================================= */

$("risk").addEventListener(
    "change",
    renderRows,
);

$("search").addEventListener(
    "input",
    renderRows,
);

$("input-search").addEventListener(
    "input",
    renderInputRows,
);


$("clear").addEventListener(
    "click",
    () => {
        $("risk").value = "All";
        $("search").value = "";

        renderRows();

        $("search").focus();
    },
);


/* =========================================================
   DIALOG EVENTS
========================================================= */

$("close").addEventListener(
    "click",
    () => {
        $("details").close();
    },
);


$("details").addEventListener(
    "click",
    event => {
        if (
            event.target ===
            $("details")
        ) {
            $("details").close();
        }
    },
);


/* =========================================================
   INITIAL STATE
========================================================= */

replaceText(
    "status",
    "Ready",
);

startPolling();