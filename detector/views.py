from django.shortcuts import render
from django.core.files.storage import FileSystemStorage
from django.views.decorators.csrf import csrf_exempt  # NEW: Imports the security bypass
from .forms import NetworkCaptureUploadForm
from .utils import extract_features_from_uploaded_file, analyze_capture
import os
import traceback

@csrf_exempt  # NEW: Tells Django to skip the CSRF token check for this specific view
def dashboard_view(request):
    results = None
    metrics = {}

    if request.method == 'POST':
# ... (keep the rest of your code exactly the same below this line)
        form = NetworkCaptureUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = request.FILES['capture_file']
            
            # 1. Save the file temporarily to the hard drive so Scapy can read it
            fs = FileSystemStorage()
            filename = fs.save(uploaded_file.name, uploaded_file)
            file_path = fs.path(filename)
            
            try:
                # 2. Pass the physical file path to our ML engine
                df_features = extract_features_from_uploaded_file(file_path, uploaded_file.name)
                df_analyzed, inference_time = analyze_capture(df_features)

                total_packets = len(df_analyzed)
                anomalies = int((df_analyzed['Prediction'] == 1).sum())
                benign = total_packets - anomalies
                latency_ms = round((inference_time / total_packets) * 1000, 3) if total_packets > 0 else 0

                metrics = {
                    'total_packets': total_packets,
                    'anomalies_flagged': anomalies,
                    'benign_count': benign,
                    'inference_latency_ms': latency_ms,
                    'total_time_seconds': round(inference_time, 4),
                    'filename': uploaded_file.name
                }

                results = df_analyzed.head(200).to_dict(orient='records')
            except Exception as e:
                # NEW: Force the full error log to print in your VS Code terminal
                print("\n" + "="*50)
                print("CRASH DETECTED IN VIEWS.PY")
                print("="*50)
                traceback.print_exc()
                print("="*50 + "\n")

                # Send the error to the front-end if anything crashes
                form.add_error(None, f"Processing error: {str(e)}")
            finally:
                # 3. Clean up: Delete the temporary file
                if os.path.exists(file_path):
                    os.remove(file_path)
    else:
        form = NetworkCaptureUploadForm()

    return render(request, 'detector/dashboard.html', {
        'form': form,
        'results': results,
        'metrics': metrics
    })