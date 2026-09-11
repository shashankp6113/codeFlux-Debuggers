import { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Plus, Loader } from 'lucide-react';
import { api } from '../lib/api';

export default function UploadButton({ label = "New Analysis", icon = <Plus size={18} />, className = "btn-primary" }) {
  const fileInputRef = useRef(null);
  const [uploading, setUploading] = useState(false);
  const navigate = useNavigate();

  const handleFileChange = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    if (!file.name.toLowerCase().endsWith('.eml')) {
      alert("Please select a valid .eml file.");
      event.target.value = null;
      return;
    }

    try {
      setUploading(true);
      const newEmail = await api.uploadEmail(file);
      if (newEmail && newEmail.id) {
        navigate(`/emails/${newEmail.id}`);
      } else {
        throw new Error("Upload succeeded but no ID was returned.");
      }
    } catch (err) {
      console.error(err);
      alert(`Upload Failed: ${err.message || "Failed to upload email."}`);
    } finally {
      setUploading(false);
      event.target.value = null; // Reset input so same file can be uploaded again if needed
    }
  };

  return (
    <>
      <button 
        className={className} 
        onClick={() => fileInputRef.current?.click()}
        disabled={uploading}
      >
        {uploading ? <Loader size={18} style={{ animation: 'spin 2s linear infinite' }} /> : icon}
        {uploading ? "Uploading..." : label}
      </button>
      
      <input 
        type="file" 
        accept=".eml"
        ref={fileInputRef} 
        style={{ display: 'none' }} 
        onChange={handleFileChange}
      />
    </>
  );
}
