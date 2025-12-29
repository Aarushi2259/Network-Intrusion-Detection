document.getElementById("uploadForm").onsubmit = async function(e) {
    e.preventDefault();

    const formData = new FormData(this);
    const response = await fetch("/analyze", {
        method: "POST",
        body: formData
    });

    const data = await response.json();
    const table = document.getElementById("resultTable");
    table.innerHTML = "";

    for (let row of data.results) {
        table.innerHTML += `
        <tr>
            <td>${row.source}</td>
            <td>${row.destination}</td>
            <td>${row.protocol}</td>
            <td>${row.packets}</td>
            <td>${row.prediction}</td>
        </tr>`;
    }

    const ctx = document.getElementById("attackChart");
    new Chart(ctx, {
        type: "pie",
        data: {
            labels: Object.keys(data.stats),
            datasets: [{
                data: Object.values(data.stats),
                backgroundColor: ["green","red","orange","purple","gold"]
            }]
        }
    });
};
