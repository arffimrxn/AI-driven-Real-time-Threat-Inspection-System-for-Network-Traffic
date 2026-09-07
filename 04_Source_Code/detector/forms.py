from django import forms

class NetworkCaptureUploadForm(forms.Form):
    capture_file = forms.FileField(
        label="Select PCAP or CSV File",
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': '.pcap,.pcapng,.csv'})
    )