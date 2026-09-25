import pdfkit
import platform
import os

def get_wkhtmltopdf_path():
    system = platform.system()
    if system == 'Windows':
        # Windows installation path
        return 'C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe'
    elif system == 'Darwin':
        # macOS installation path
        return '/usr/local/bin/wkhtmltopdf'
    elif system == 'Linux':
        # Linux installation path
        return '/usr/local/bin/wkhtmltopdf'
    else:
        raise Exception(f"Unsupported operating system: {system}")

path_to_wkhtmltopdf = get_wkhtmltopdf_path()

if not os.path.isfile(path_to_wkhtmltopdf):
    raise FileNotFoundError(f"wkhtmltopdf executable not found at: {path_to_wkhtmltopdf}")

pdfkit_config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)