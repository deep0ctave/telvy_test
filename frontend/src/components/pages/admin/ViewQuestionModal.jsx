// File: components/pages/Questions/ViewQuestionModal.jsx
import React from "react";
import { X } from "lucide-react";

const ViewQuestionModal = ({ question, onClose }) => {
  if (!question) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-40 z-50 flex items-center justify-center">
      <div className="bg-base-100 rounded-lg w-full max-w-2xl shadow-lg relative">
        <div className="p-6 border-b border-base-300 flex justify-between items-center">
          <h2 className="text-xl font-semibold">View Question</h2>
          <button onClick={onClose} className="btn btn-sm btn-circle btn-ghost">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <label className="label font-semibold">Question Text:</label>
            <div className="p-3 rounded bg-base-200">{question.question_text}</div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="label font-semibold">Question Type:</label>
              <div className="badge badge-info badge-outline">{question.question_type}</div>
            </div>

            <div>
              <label className="label font-semibold">Status:</label>
              <div className={`badge ${question.published ? "badge-success" : "badge-warning"}`}>
                {question.published ? "Published" : "Draft"}
              </div>
            </div>
          </div>

          <div>
            <label className="label font-semibold">Tags:</label>
            <div className="flex gap-2 flex-wrap">
              {question.tags?.length > 0 ? (
                question.tags.map((tag, idx) => (
                  <span key={idx} className="badge badge-outline">{tag}</span>
                ))
              ) : (
                <span className="text-sm text-base-content/50">No tags</span>
              )}
            </div>
          </div>

          <div>
            <label className="label font-semibold">Created By:</label>
            <p>{question.owner?.name || "Unknown"}</p>
          </div>

          {/* Conditional content based on type */}
          {question.question_type === "mcq" && (
            <div>
              <label className="label font-semibold">Options:</label>
              <ul className="list-disc pl-5">
                {question.options?.map((opt, i) => (
                  <li key={i}>{opt}</li>
                ))}
              </ul>
            </div>
          )}

          {question.question_type === "true_false" && (
            <div>
              <label className="label font-semibold">Options:</label>
              <div className="space-x-2">
                <span className="badge badge-outline">True</span>
                <span className="badge badge-outline">False</span>
              </div>
            </div>
          )}

          {question.question_type === "type_in" && (
            <div>
              <label className="label font-semibold">Answer Format:</label>
              <span className="badge badge-neutral">Free Text</span>
            </div>
          )}
        </div>

        <div className="p-4 border-t border-base-300 text-right">
          <button className="btn" onClick={onClose}>Close</button>
        </div>
      </div>
    </div>
  );
};

export default ViewQuestionModal;
