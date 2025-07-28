from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def generar_pdf(nombre, resultado, detalles):
    c = canvas.Canvas(nombre, pagesize=A4)
    width, height = A4

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, height - 50, "Obice - Informe de Análisis")

    c.setFont("Helvetica", 12)
    c.drawString(50, height - 100, f"Resultado general: {resultado}")
    c.drawString(50, height - 120, "Detalles:")

    y = height - 140
    for linea in detalles.split('\n'):
        c.drawString(60, y, linea)
        y -= 15

    c.save()
