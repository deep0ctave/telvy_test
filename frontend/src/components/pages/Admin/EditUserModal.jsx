// components/pages/Admin/EditUserModal.jsx
import React, { useEffect, useState } from "react";
import DatePicker from "react-datepicker";
import "react-datepicker/dist/react-datepicker.css";
import { toast } from "react-toastify";
import { fetchSchoolSuggestions, updateUserById } from "../../../services/api";

const classes = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"];
const sections = ["A", "B", "C", "D", "E"];
const genders = ["male", "female", "other"];
const userTypes = ["student", "teacher", "admin"];

const EditUserModal = ({ user, onClose, onSave }) => {
  const [form, setForm] = useState({
    ...user,
    dob: user.dob ? new Date(user.dob) : null,
  });

  const [schoolOptions, setSchoolOptions] = useState([]);

  useEffect(() => {
    if (form.school?.length > 1) handleSchoolSearch(form.school);
  }, []);

  const handleSchoolSearch = async (q) => {
    const results = await fetchSchoolSuggestions(q);
    setSchoolOptions(results);
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setForm((f) => ({ ...f, [name]: value }));
    if (name === "school") handleSchoolSearch(value);
  };

  const handleSave = async () => {
    try {
      const payload = {
        ...form,
        dob: form.dob ? form.dob.toISOString().split("T")[0] : null,
      };

      delete payload.username; // Don't update username
      const updated = await updateUserById(user.id, payload);
      toast.success("User updated successfully");
      onSave({ ...form, id: user.id });
      onClose();
    } catch (err) {
      const msg =
        err?.response?.data?.error ||
        err?.response?.data?.errors?.[0]?.msg ||
        "Failed to update user";
      toast.error(msg);
    }
  };

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-2xl">
        <h2 className="font-bold text-xl mb-4">Edit User</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="input">
            <span className="label">Username</span>
            <input value={form.username} disabled className="bg-base-200" />
          </label>

          <label className="input">
            <span className="label">Full Name</span>
            <input
              name="name"
              value={form.name}
              onChange={handleChange}
              placeholder="Full name"
            />
          </label>

          <label className="input">
            <span className="label">Phone</span>
            <input
              name="phone"
              value={form.phone}
              onChange={handleChange}
              placeholder="Phone"
            />
          </label>

          <label className="input">
            <span className="label">Email</span>
            <input
              name="email"
              value={form.email}
              onChange={handleChange}
              placeholder="Email"
              type="email"
            />
          </label>

          <label className="input">
            <span className="label">Gender</span>
            <select
              className="select select-bordered w-full"
              name="gender"
              value={form.gender || ""}
              onChange={handleChange}
            >
              <option value="">Select Gender</option>
              {genders.map((g) => (
                <option key={g}>{g}</option>
              ))}
            </select>
          </label>

          <label className="input">
            <span className="label">DOB</span>
            <DatePicker
              selected={form.dob}
              onChange={(date) => setForm({ ...form, dob: date })}
              dateFormat="dd-MM-yyyy"
              placeholderText="Select DOB"
              className="input input-bordered w-full"
              showMonthDropdown
              showYearDropdown
              dropdownMode="select"
            />
          </label>

          <label className="input">
            <span className="label">User Type</span>
            <select
              className="select select-bordered w-full"
              name="user_type"
              value={form.user_type}
              onChange={handleChange}
            >
              {userTypes.map((type) => (
                <option key={type}>{type}</option>
              ))}
            </select>
          </label>

          <label className="input">
            <span className="label">Verified</span>
            <select
              className="select select-bordered w-full"
              name="is_verified"
              value={form.is_verified ? "true" : "false"}
              onChange={(e) =>
                setForm((f) => ({ ...f, is_verified: e.target.value === "true" }))
              }
            >
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </label>

          <label className="input col-span-1 md:col-span-2">
            <span className="label">School</span>
            <input
              name="school"
              value={form.school}
              onChange={handleChange}
              placeholder="School name"
              list="school-suggestions"
            />
            <datalist id="school-suggestions">
              {schoolOptions.map((s) => (
                <option key={s} value={s} />
              ))}
            </datalist>
          </label>

          <label className="input">
            <span className="label">Class</span>
            <select
              className="select select-bordered w-full"
              name="class"
              value={form.class}
              onChange={handleChange}
            >
              <option value="">Select</option>
              {classes.map((c) => (
                <option key={c}>{c}</option>
              ))}
            </select>
          </label>

          <label className="input">
            <span className="label">Section</span>
            <select
              className="select select-bordered w-full"
              name="section"
              value={form.section}
              onChange={handleChange}
            >
              <option value="">Select</option>
              {sections.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          </label>
        </div>

        <div className="modal-action">
          <button className="btn btn-outline" onClick={onClose}>
            Cancel
          </button>
          <button className="btn btn-primary" onClick={handleSave}>
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
};

export default EditUserModal;
