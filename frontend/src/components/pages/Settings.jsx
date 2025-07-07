import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';

const Settings = () => {
  const { user, fetchProfile } = useAuth();

  const [formData, setFormData] = useState({
    username: '',
    user_type: '',
    name: '',
    email: '',
    phone: '',
    school: '',
    class: '',
    section: '',
    gender: '',
    dob: '',
    newPassword: '',
    confirmPassword: '',
    oldPassword: '',
  });

  useEffect(() => {
    if (user) {
      const actualUser = user.user || user;
      setFormData((prev) => ({
        ...prev,
        username: actualUser.username || '',
        user_type: actualUser.user_type || '',
        name: actualUser.name || '',
        email: actualUser.email || '',
        phone: actualUser.phone || '',
        school: actualUser.school || '',
        class: actualUser.class || '',
        section: actualUser.section || '',
        gender: actualUser.gender || '',
        dob: actualUser.dob?.slice(0, 10) || '',
      }));
    }
  }, [user]);

  const [showOtpModal, setShowOtpModal] = useState(false);
  const [otp, setOtp] = useState('');
  const [otpPurpose, setOtpPurpose] = useState('');

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setOtpPurpose('profile');
    setShowOtpModal(true);
  };

  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    if (formData.newPassword !== formData.confirmPassword) {
      alert('New passwords do not match');
      return;
    }
    setOtpPurpose('password');
    setShowOtpModal(true);
  };

  const handleOtpSubmit = () => {
    setShowOtpModal(false);
    console.log('Verifying OTP:', otp, 'for', otpPurpose);
    // Simulate backend verification/update
  };

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-2xl font-bold">Settings</h1>

      <div role="tablist" className="tabs tabs-bordered">
        {/* Profile tab */}
        <input type="radio" name="settings_tabs" role="tab" className="tab" aria-label="Profile" defaultChecked />
        <div role="tabpanel" className="tab-content p-4 border-base-300 bg-base-100 rounded-box space-y-6">
          <form onSubmit={handleSubmit} className="space-y-8">
            {/* Profile Info */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <fieldset className="fieldset">
                <legend className="fieldset-legend">Username</legend>
                <input type="text" name="username" className="input" value={formData.username} disabled />
                <p className="label">Cannot be changed</p>
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">User Type</legend>
                <input type="text" name="user_type" className="input" value={formData.user_type} disabled />
                <p className="label">Cannot be changed</p>
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">Full Name</legend>
                <input type="text" name="name" className="input" value={formData.name} onChange={handleChange} />
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">Email</legend>
                <input type="email" name="email" className="input" value={formData.email} onChange={handleChange} />
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">Phone</legend>
                <input type="tel" name="phone" className="input" value={formData.phone} onChange={handleChange} />
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">Gender</legend>
                <input type="text" name="gender" className="input" value={formData.gender} onChange={handleChange} />
              </fieldset>

              <fieldset className="fieldset">
                <legend className="fieldset-legend">Date of Birth</legend>
                <input type="date" name="dob" className="input" value={formData.dob} onChange={handleChange} />
              </fieldset>
            </div>

            {/* School Info (for students) */}
            {formData.user_type === 'student' && (
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                <fieldset className="fieldset">
                  <legend className="fieldset-legend">School</legend>
                  <input
                    type="text"
                    name="school"
                    className="input"
                    value={formData.school}
                    onChange={handleChange}
                  />
                </fieldset>
                <fieldset className="fieldset">
                  <legend className="fieldset-legend">Class</legend>
                  <input
                    type="text"
                    name="class"
                    className="input"
                    value={formData.class}
                    onChange={handleChange}
                  />
                </fieldset>
                <fieldset className="fieldset">
                  <legend className="fieldset-legend">Section</legend>
                  <input
                    type="text"
                    name="section"
                    className="input"
                    value={formData.section}
                    onChange={handleChange}
                  />
                </fieldset>
              </div>
            )}

            <button type="submit" className="btn btn-primary mt-2">
              Save Changes
            </button>
          </form>
        </div>

        {/* Security tab */}
        <input type="radio" name="settings_tabs" role="tab" className="tab" aria-label="Security" />
        <div role="tabpanel" className="tab-content p-4 border-base-300 bg-base-100 rounded-box">
          <form onSubmit={handlePasswordSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <fieldset className="fieldset">
              <legend className="fieldset-legend">Current Password</legend>
              <input
                type="password"
                name="oldPassword"
                className="input"
                value={formData.oldPassword}
                onChange={handleChange}
                required
              />
            </fieldset>

            <fieldset className="fieldset">
              <legend className="fieldset-legend">New Password</legend>
              <input
                type="password"
                name="newPassword"
                className="input"
                value={formData.newPassword}
                onChange={handleChange}
                required
              />
            </fieldset>

            <fieldset className="fieldset">
              <legend className="fieldset-legend">Confirm New Password</legend>
              <input
                type="password"
                name="confirmPassword"
                className="input"
                value={formData.confirmPassword}
                onChange={handleChange}
                required
              />
            </fieldset>

            <div className="md:col-span-2">
              <button type="submit" className="btn btn-warning mt-2">
                Change Password
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* OTP Modal */}
      {showOtpModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-base-100 rounded-box shadow-lg p-6 w-96">
            <h3 className="text-lg font-bold mb-2">OTP Verification</h3>
            <input
              type="text"
              className="input input-bordered w-full mb-4"
              placeholder="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
            <div className="flex justify-end gap-2">
              <button className="btn btn-outline" onClick={() => setShowOtpModal(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={handleOtpSubmit}>
                Verify
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Settings;
