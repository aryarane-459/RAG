import pymupdf


def Pdf_to_Text(Pdf_path, text_path):

    doc = pymupdf.open(Pdf_path)

    text = ""

    for page_num, page in enumerate(doc):

        page_text = page.get_text()

        text += f"--- page {page_num + 1} ---\n"
        text += page_text
        text += "\n"

    with open(text_path, "w", encoding="utf-8") as f:
        f.write(text)

    print("The pdf is converted successfully")

    return text
