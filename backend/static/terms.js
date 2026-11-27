// 약관 「모두 동의」(#143): 스크립트가 있을 때만 보인다. 서버는 각 항목 체크만 받는다.
(function () {
  var all = document.querySelector("[data-agree-all]");
  if (!all) return;
  var form = all.form;
  var items = Array.prototype.filter.call(form.querySelectorAll('input[type="checkbox"]'), function (box) {
    return box !== all;
  });
  function sync() {
    var checked = items.filter(function (box) { return box.checked; }).length;
    all.checked = checked === items.length;
    all.indeterminate = checked > 0 && checked < items.length;
  }
  all.addEventListener("change", function () {
    items.forEach(function (box) { box.checked = all.checked; });
    all.indeterminate = false;
  });
  items.forEach(function (box) { box.addEventListener("change", sync); });
  sync();
  all.closest("[data-slot=agree-all]").hidden = false;
})();
