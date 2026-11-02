(() => {
  for (const id of [
    'add-drive-command',
    'sha256-register-command',
    'sha256-command'
  ]) {
    const field = document.getElementById(id);
    if (!field) continue;

    field.addEventListener('focus', () => field.select());
    field.addEventListener('click', () => field.select());
  }
})();
