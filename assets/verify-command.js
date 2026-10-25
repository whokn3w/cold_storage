(() => {
  for (const id of [
    'sha256-register-command',
    'sha256-command'
  ]) {
    const field = document.getElementById(id);
    if (!field) continue;

    field.addEventListener('focus', () => field.select());
    field.addEventListener('click', () => field.select());
  }
})();
