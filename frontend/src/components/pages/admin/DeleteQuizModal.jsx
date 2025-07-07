import React, { useState } from "react";
import { toast } from "react-toastify";
import { deleteFullQuiz } from "../../../services/api";

const DeleteQuizModal = ({ quiz, onClose, onDelete }) => {
  const [loading, setLoading] = useState(false);

  const handleDelete = async () => {
    setLoading(true);
    try {
      await deleteFullQuiz(quiz.id);
      toast.success("Quiz deleted successfully");
      onDelete(quiz.id);
      onClose();
    } catch (err) {
      toast.error(err?.response?.data?.message || "Failed to delete quiz");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-md p-6">
        <h3 className="font-bold text-lg mb-4 text-error">Confirm Delete</h3>
        <p className="mb-4">
          Are you sure you want to delete the quiz <strong>{quiz.title}</strong>?
          This action cannot be undone.
        </p>

        <div className="modal-action">
          <button className="btn" onClick={onClose} disabled={loading}>
            Cancel
          </button>
          <button
            className="btn btn-error"
            onClick={handleDelete}
            disabled={loading}
          >
            {loading ? "Deleting..." : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default DeleteQuizModal;
