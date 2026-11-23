
const logout = document.getElementById("logout");

logout.addEventListener("click", async () => {
    await fetch("/api/logout", {
        method: "POST"
    });

    window.location.href = "/login.html";
});

const grafico1 = document.getElementById("grafico");

function carregarGraficos() {
    grafico1.src = "/api/graficos";
}

carregarGraficos();

const botao = document.getElementById("GerarPdf");

botao.addEventListener("click", async () => {
    try {
        const resposta = await fetch("/api/pdf");

        if (resposta.status === 401) {
            window.location.href = "/login.html";
            return;
        }

        if (!resposta.ok) {
            const erro = await resposta.json();
            throw new Error(erro.erro);
        }

        const arquivo = await resposta.blob();
        const url = URL.createObjectURL(arquivo);

        const link = document.createElement("a");
        link.href = url;
        link.download = "Relatorios67.pdf";

        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(url), 1000);

    } catch (erro) {
        console.log(erro);
    }
});
