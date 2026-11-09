// Actualiza automáticamente los bloques con data-url (sin recargar la página completa).
(function () {
  function construirUrl(el) {
    var url = el.getAttribute("data-url");
    var sep = url.indexOf("?") >= 0 ? "&" : "?";
    var formSel = el.getAttribute("data-form");
    if (formSel) {
      var f = document.querySelector(formSel);
      if (f) {
        var params = new URLSearchParams(new FormData(f)).toString();
        if (params) { url += sep + params; sep = "&"; }
      }
    }
    return url + sep + "parcial=1";
  }
  function refrescar(el) {
    var a = document.activeElement;
    if (a && el.contains(a) && (a.tagName === "TEXTAREA" || a.tagName === "INPUT")) { return; }
    fetch(construirUrl(el), { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) { throw new Error(r.status); } return r.text(); })
      .then(function (html) { el.innerHTML = html; })
      .catch(function () {});
  }
  document.querySelectorAll("[data-url]").forEach(function (el) {
    var seg = parseInt(el.getAttribute("data-intervalo") || "10", 10);
    setInterval(function () { refrescar(el); }, seg * 1000);
  });
  document.querySelectorAll("[data-actualizar]").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var el = document.querySelector(btn.getAttribute("data-actualizar"));
      if (el) { refrescar(el); }
    });
  });
})();

/* Mostrar u ocultar contraseña */
document.querySelectorAll('input[type=password]').forEach(function (i) {
  var b = document.createElement('button');
  b.type = 'button'; b.className = 'ver-clave'; b.textContent = 'Mostrar contraseña';
  b.onclick = function () { var oculto = i.type === 'password'; i.type = oculto ? 'text' : 'password'; b.textContent = oculto ? 'Ocultar contraseña' : 'Mostrar contraseña'; };
  i.insertAdjacentElement('afterend', b);
});
