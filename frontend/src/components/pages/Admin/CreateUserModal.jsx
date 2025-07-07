import React, { useState, useEffect } from "react";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import { createUser, fetchSchoolSuggestions } from "../../../services/api";
import { toast } from "react-toastify";

const CreateUserModal = ({ onClose, onCreate }) => {
  const [form, setForm] = useState({
    username: "",
    password: "",
    phone: "",
    email: "",
    name: "",
    gender: "",
    dob: null,
    user_type: "",
    is_verified: false,
    school: "",
    class: "",
    section: "",
  });

  const [schoolSuggestions, setSchoolSuggestions] = useState([]);

  const handleChange = (key, val) => {
    setForm((prev) => ({ ...prev, [key]: val }));
  };

  const handleSubmit = async () => {
    try {
      const payload = {
        ...form,
        dob: form.dob ? form.dob.toISOString().split("T")[0] : null,
      };
      const res = await createUser(payload);
      onCreate(res.user);
      onClose();
    } catch (err) {
      toast.error(err?.response?.data?.error || "Failed to create user");
    }
  };

  useEffect(() => {
    const fetchSchools = async () => {
      const list = await fetchSchoolSuggestions(form.school);
      setSchoolSuggestions(list);
    };
    if (form.school.length > 1) fetchSchools();
  }, [form.school]);

  return (
    <dialog open className="modal modal-open">
      <div className="modal-box space-y-4 max-w-2xl">
        <h3 className="font-bold text-lg">Create User</h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="input">
            <span className="label">Username</span>
            <input value={form.username} onChange={(e) => handleChange("username", e.target.value)} />
          </label>

          <label className="input">
            <span className="label">Password</span>
            <input type="password" value={form.password} onChange={(e) => handleChange("password", e.target.value)} />
          </label>

          <label className="input">
            <span className="label">Phone</span>
            <input value={form.phone} onChange={(e) => handleChange("phone", e.target.value)} />
          </label>

          <label className="input">
            <span className="label">Email</span>
            <input value={form.email} onChange={(e) => handleChange("email", e.target.value)} />
          </label>

          <label className="input">
            <span className="label">Name</span>
            <input value={form.name} onChange={(e) => handleChange("name", e.target.value)} />
          </label>

          <label className="input">
            <span className="label">Gender</span>
            <select className="select" value={form.gender} onChange={(e) => handleChange("gender", e.target.value)}>
              <option disabled value="">Select gender</option>
              <option>male</option>
              <option>female</option>
              <option>other</option>
            </select>
          </label>

          <label className="input">
            <span className="label">DOB</span>
            <DatePicker
              selected={form.dob}
              onChange={(date) => handleChange("dob", date)}
              dateFormat="dd-MM-yyyy"
              className="input input-bordered w-full"
              placeholderText="Select date"
            />
          </label>

          <label className="input">
            <span className="label">School</span>
            <input
              list="school-options"
              value={form.school}
              onChange={(e) => handleChange("school", e.target.value)}
            />
            <datalist id="school-options">
              {schoolSuggestions.map((s, i) => (
                <option key={i} value={s} />
              ))}
            </datalist>
          </label>

          <label className="input">
            <span className="label">Class</span>
            <select className="select" value={form.class} onChange={(e) => handleChange("class", e.target.value)}>
              <option disabled value="">Select</option>
              {[...Array(12)].map((_, i) => <option key={i}>{i + 1}</option>)}
            </select>
          </label>

          <label className="input">
            <span className="label">Section</span>
            <select className="select" value={form.section} onChange={(e) => handleChange("section", e.target.value)}>
              <option disabled value="">Select</option>
              {["A", "B", "C", "D"].map((sec) => <option key={sec}>{sec}</option>)}
            </select>
          </label>

          <label className="input">
            <span className="label">User Type</span>
            <select className="select" value={form.user_type} onChange={(e) => handleChange("user_type", e.target.value)}>
              <option disabled value="">Select</option>
              <option>student</option>
              <option>teacher</option>
              <option>admin</option>
            </select>
          </label>

          <label className="input">
            <span className="label">Verified?</span>
            <select className="select" value={form.is_verified} onChange={(e) => handleChange("is_verified", e.target.value === "true")}>
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </label>
        </div>

        <div className="modal-action">
          <button className="btn btn-primary" onClick={handleSubmit}>Create</button>
          <button className="btn" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </dialog>
  );
};

export default CreateUserModal;
