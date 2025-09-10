$(function () {
  $('[data-toggle="tooltip"]').tooltip()
})
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("pre").forEach((block) => {
    // Create button
    let button = document.createElement("button");
    button.className = "copy-btn";
    button.innerText = "Copy";

    // Copy logic
    button.addEventListener("click", () => {
      let code = block.innerText;
      navigator.clipboard.writeText(code).then(() => {
        button.innerText = "Copied!";
        setTimeout(() => {
          button.innerText = "Copy";
        }, 1500);
      });
    });

    block.appendChild(button);
  });
});
