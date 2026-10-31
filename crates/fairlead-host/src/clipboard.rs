//! The one clipboard handler both HTML surfaces carry: the admin console's
//! "token 只显示这一遍" page and the edge's install page.
//!
//! A button says what to copy in one of two ways: `data-text="…"` holds the
//! text itself (the install page, whose command is generated per request), or
//! `data-copy="id"` names a box whose `innerText` is the text (the token page,
//! where the text is already on screen and must not be duplicated in an
//! attribute).
//!
//! `navigator.clipboard` only exists in a secure context, and both pages are
//! normally opened over plain HTTP -- a LAN address or the relay's IP:port --
//! so fall back to the textarea + `execCommand` trick. If the browser refuses
//! that too (no user gesture, a locked-down profile), select the text so a
//! ⌘C/ctrl-C still finishes the job, and say so on the button.
pub(crate) const COPY_JS: &str = r#"<script>
function fairleadCopyTarget(b) {
  if (b.dataset.text != null) return { text: b.dataset.text, el: null };
  var el = b.dataset.copy ? document.getElementById(b.dataset.copy) : null;
  return { text: el ? (el.innerText || el.textContent || "") : "", el: el };
}
document.addEventListener("click", function (e) {
  var b = e.target.closest("[data-copy],[data-text]");
  if (!b || b.tagName !== "BUTTON") return;
  var t = fairleadCopyTarget(b);
  var label = b.dataset.label || b.textContent || "复制";
  b.dataset.label = label;
  var restore = function (ms) { setTimeout(function () { b.textContent = label; }, ms); };
  var done = function () { b.textContent = "已复制"; restore(1400); };
  var fail = function () {
    if (!t.el) return restore(1400);
    var r = document.createRange();
    r.selectNodeContents(t.el);
    var s = window.getSelection();
    s.removeAllRanges();
    s.addRange(r);
    b.textContent = "已选中，按 ⌘C";
    restore(2600);
  };
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(t.text).then(done, fail);
    return;
  }
  var a = document.createElement("textarea");
  a.value = t.text;
  a.style.position = "fixed";
  a.style.top = "-1000px";
  a.style.opacity = "0";
  document.body.appendChild(a);
  a.select();
  var copied = false;
  try { copied = document.execCommand("copy"); } catch (err) { copied = false; }
  document.body.removeChild(a);
  copied ? done() : fail();
});
</script>"#;
