/* global Dropzone */

Dropzone.options.transferDropzone = {
    method: "post", // request type
    maxFilesize: 2000, // MB
    addRemoveLinks: true,
    createImageThumbnails: false,

    init: function () {
        this.on("success", function (file, responseText) {
            // add link
            var link = document.createElement("a");
            link.setAttribute("href", responseText);
            link.setAttribute("class", "dz-remove");
            link.appendChild(document.createTextNode("Download link"));
            file.previewTemplate.appendChild(link);
        });
    }
};