function togglePass() {
    const passField = document.querySelector('input[name="password"]');
    passField.type = passField.type === 'password' ? 'text' : 'password';
}