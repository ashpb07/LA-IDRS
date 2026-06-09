# ── Python virtual environment ─────────────────────────────────────────────
echo ""
echo "[2/5] Setting up Python virtual environment …"

cd "$ROOT"

# Drop privileges for venv creation if running as root
if [ "$EUID" -eq 0 ] && [ -n "${SUDO_USER:-}" ]; then
    VENV_CMD="sudo -u $SUDO_USER"
else
    VENV_CMD=""
fi

if [ ! -d ".venv" ]; then
    $VENV_CMD python3.12 -m venv .venv || $VENV_CMD python3 -m venv .venv
    echo "  Created .venv"
fi

# Activate and install as the actual user
$VENV_CMD .venv/bin/pip install --upgrade pip
$VENV_CMD .venv/bin/pip install -r requirements.txt
echo "  Python dependencies installed."