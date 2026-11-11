"""Read-only presentation of saved Cold Storage verification history.

Registration, verification, and historical issues remain distinct.
This module never reads archive files or changes catalog records.
"""


def render_verification_history(db, esc, when):
    total = db.execute(
        "SELECT COUNT(*) FROM runs"
    ).fetchone()[0]

    runs = db.execute(
        "SELECT drive_id,seq,stamp,action,result,tracked,delta,issues "
        "FROM runs "
        "ORDER BY stamp DESC,drive_id ASC,seq DESC LIMIT 200"
    ).fetchall()

    parts = [
        '<section class="panel">',
        '<h2>Verification and registration history</h2>',
        '<p class="muted">Showing the latest '
        + str(len(runs)) + ' of ' + str(total)
        + ' recorded operations. SHA-256 registration records '
        'a checksum baseline; it is not a full verification.</p>',
    ]

    if runs:
        parts.extend([
            '<div class="drive-table"><table>',
            '<tr><th>Local Time</th><th>Drive</th>'
            '<th>Operation</th><th>Result</th>'
            '<th>Tracked Files</th>'
            '<th>Changes / Unregistered</th>'
            '<th>Issues</th></tr>',
        ])

        for row in runs:
            action = row["action"]
            result = row["result"]

            if action == "verify":
                operation = "SHA-256 verification"
                delta_label = "Unregistered files"
            else:
                operation = "SHA-256 registration"
                delta_label = "New checksums"

            if result == "PASS":
                result_label = (
                    "Verification passed"
                    if action == "verify"
                    else "Registration completed"
                )
                color = "good"

            elif result == "FAIL":
                result_label = (
                    "Verification failed"
                    if action == "verify"
                    else "Registration failed"
                )
                color = "bad"

            elif result == "INCOMPLETE":
                result_label = (
                    "Verification incomplete"
                    if action == "verify"
                    else "Registration incomplete"
                )
                color = "warn"

            elif result == "NO_CHANGES":
                result_label = "No new checksums"
                color = "muted"

            else:
                result_label = "Review: " + str(result)
                color = "warn"

            issue_count = (
                "Unknown (incomplete)"
                if row["issues"] < 0
                else str(row["issues"])
            )

            parts.append(
                "<tr>"
                "<td>" + esc(str(when(row["stamp"]))) + "</td>"
                "<td><code>" + esc(str(row["drive_id"])) + "</code></td>"
                "<td>" + esc(operation) + "</td>"
                '<td><strong class="' + color + '">'
                + esc(result_label) + "</strong></td>"
                "<td>" + str(row["tracked"]) + "</td>"
                "<td><small>" + esc(delta_label) + ":</small> "
                + str(row["delta"]) + "</td>"
                "<td>" + esc(issue_count) + "</td>"
                "</tr>"
            )

        parts.append("</table></div>")
    else:
        parts.append(
            '<p class="muted">No operations recorded yet.</p>'
        )

    parts.append("</section>")

    issue_total = db.execute(
        "SELECT COUNT(*) FROM issues"
    ).fetchone()[0]

    issue_rows = db.execute(
        "SELECT drive_id,seq,raw FROM issues "
        "ORDER BY substr(raw,1,20) DESC,drive_id ASC,seq DESC "
        "LIMIT 200"
    ).fetchall()

    descriptions = {
        "UNREGISTERED": "Not in the saved SHA-256 baseline",
        "MISSING": "Registered file was missing",
        "READ_ERROR": "Registered file could not be read",
        "HASH_MISMATCH": "Computed checksum did not match",
    }

    parts.extend([
        '<section class="panel">',
        '<details><summary>Historical issue records ('
        + str(issue_total) + ')</summary>',
        '<p class="muted">These are historical observations, '
        'not necessarily unresolved failures. '
        'They are shown separately from verification runs '
        'because timestamps alone do not uniquely identify '
        'an operation.</p>',
    ])

    if issue_rows:
        parts.extend([
            '<p class="muted">Showing the latest '
            + str(len(issue_rows)) + ' issue records.</p>',
            '<div class="drive-table"><table>',
            '<tr><th>Local Time</th><th>Drive</th>'
            '<th>Issue</th><th>Recorded Path</th></tr>',
        ])

        for row in issue_rows:
            fields = row["raw"].split("\t", 2)

            if len(fields) != 3:
                stamp = ""
                kind = "INVALID RECORD"
                path = row["raw"]
            else:
                stamp, kind, path = fields

            description = descriptions.get(
                kind, "Review historical issue"
            )

            parts.append(
                "<tr>"
                "<td>" + esc(str(when(stamp))) + "</td>"
                "<td><code>" + esc(str(row["drive_id"])) + "</code></td>"
                "<td><strong>" + esc(kind) + "</strong>"
                '<div class="muted">'
                + esc(description) + "</div></td>"
                "<td><code>" + esc(path) + "</code></td>"
                "</tr>"
            )

        parts.append("</table></div>")
    else:
        parts.append(
            '<p class="muted">No historical issue records.</p>'
        )

    parts.append("</details></section>")

    return "".join(parts)
