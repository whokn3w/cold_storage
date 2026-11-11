"""Read-only HTML view of SHA-256 file-processing progress.

This component never declares a verification PASS or FAIL.
The permanent verification history remains authoritative.
"""

from verification_progress import read_progress


def render_verification_progress(device_folder, esc, when, now=None):
    progress = read_progress(device_folder, now=now)

    # Drives without a progress snapshot retain their current layout.
    if progress is None:
        return ""

    phase = progress["phase"]

    if phase == "running":
        if progress["recent"]:
            state = "Processing — recent progress update"
            explanation = (
                "The last progress update is recent. "
                "Files currently being hashed are not counted "
                "as processed until hashing finishes."
            )
        else:
            state = "No recent progress update"
            explanation = (
                "The progress record has stopped updating. "
                "Verification may have stalled or stopped. "
                "Check the host command before assuming it is active."
            )
    elif phase == "finished":
        state = "File processing completed"
        explanation = (
            "All tracked files were processed. "
            "Consult verification history for the final PASS "
            "or FAIL result."
        )
    else:
        state = "Verification interrupted"
        explanation = (
            "The operation ended before completion. "
            "This snapshot is not a successful verification."
        )

    total = progress["total"]
    processed = progress["processed"]

    parts = [
        '<section class="panel" '
        'aria-label="SHA-256 verification progress">',
        '<h3 data-progress-poll="'
        + ('true' if phase == 'running' else 'false')
        + '">SHA-256 verification progress</h3>',
        '<p><strong>' + esc(state) + '</strong></p>',
        '<p class="muted">' + esc(explanation) + '</p>',
        '<div class="drive-facts">',
        '<div><small>Files processed</small><strong>'
        + str(processed) + ' / ' + str(total)
        + '</strong></div>',
        '<div><small>Hashes calculated</small><strong>'
        + str(progress["hashed"])
        + '</strong></div>',
        '<div><small>Issues detected</small><strong>'
        + str(progress["issues"])
        + '</strong></div>',
        '<div><small>Unregistered files</small><strong>'
        + str(progress["unregistered"])
        + '</strong></div>',
        '</div>',
    ]

    if total > 0:
        percent = progress["percent"]
        parts.extend([
            '<p><strong>File-processing progress: '
            + str(percent) + '%</strong></p>',
            '<progress max="' + str(total)
            + '" value="' + str(processed)
            + '" style="width:100%;max-width:640px">'
            + str(percent) + '%</progress>',
        ])
    else:
        parts.append(
            '<p class="muted">No tracked files to process.</p>'
        )

    parts.extend([
        '<p class="muted">Last progress update: '
        + esc(when(progress["updated_at"])) + '</p>',
        '<p class="muted">Processing percentages do not indicate '
        'successful checksum verification. '
        '<a href="/history">View verification history</a>.</p>',
        '</section>',
    ])

    return "".join(parts)
