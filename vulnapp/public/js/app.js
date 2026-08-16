'use strict';

(function () {
  function toast(msg) {
    var el = document.getElementById('toast');
    if (!el) {
      el = document.createElement('div');
      el.id = 'toast';
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.classList.add('show');
    setTimeout(function () { el.classList.remove('show'); }, 2500);
  }

  var form = document.getElementById('comment-form');
  if (form) {
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var fd = new FormData(form);
      fetch(form.action, { method: 'POST', body: fd })
        .then(function (r) { return r.text(); })
        .then(function () {
          var box = document.getElementById('comments');
          var body = fd.get('body');
          var node = document.createElement('div');
          node.className = 'comment';
          node.innerHTML = '<strong>you</strong> <span class="muted">just now</span><p>' + body + '</p>';
          box.appendChild(node);
          form.reset();
          toast('Comment posted');
        })
        .catch(function () { toast('Failed to post comment'); });
    });
  }

  var fileInput = document.querySelector('input[type="file"]');
  if (fileInput) {
    fileInput.addEventListener('change', function () {
      var f = fileInput.files[0];
      if (f) { toast('Selected: ' + f.name + ' (' + f.size + ' bytes)'); }
    });
  }

  window.VulnApp = { toast: toast };
})();