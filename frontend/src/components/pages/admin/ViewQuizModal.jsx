import React from "react";
import { X } from "lucide-react";

const ViewQuizModal = ({ quiz, onClose }) => {
  return (
    <dialog className="modal modal-open">
      <div className="modal-box max-w-4xl">
        <div className="flex justify-between items-center mb-4">
          <h3 className="text-lg font-bold">View Quiz: {quiz.title}</h3>
          <button className="btn btn-sm btn-circle" onClick={onClose}>
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-2">
          <div>
            <strong>Status:</strong>{" "}
            <span className={`badge badge-${statusColor(quiz.status)}`}>
              {quiz.status}
            </span>
          </div>
          <div>
            <strong>Tags:</strong>{" "}
            <span className="flex flex-wrap gap-1">
              {quiz.tags?.map((tag) => (
                <span key={tag} className="badge badge-accent badge-sm">
                  {tag}
                </span>
              ))}
            </span>
          </div>
          <div>
            <strong>Total Questions:</strong> {quiz.questions?.length || 0}
          </div>
          <div>
            <strong>Created By:</strong> {quiz.created_by || "-"}
          </div>
        </div>

        <div className="divider">Questions</div>

        {quiz.questions?.length === 0 ? (
          <p className="text-sm text-gray-500">No questions added yet.</p>
        ) : (
          <div className="space-y-6 max-h-[60vh] overflow-y-auto">
            {quiz.questions.map((q, index) => (
              <div
                key={q.id || index}
                className="p-4 border border-base-300 rounded-md"
              >
                <div className="mb-2 text-sm text-gray-500">
                  Q{index + 1} • <span className="capitalize">{q.question_type}</span>
                </div>
                <div className="font-medium">{q.question_text}</div>

                {q.question_image && (
                  <img
                    src={q.question_image}
                    alt="Question"
                    className="my-2 max-w-xs rounded-md border"
                  />
                )}

                {q.question_type === "mcq" && (
                  <div className="mt-2 space-y-1">
                    {q.options.map((opt) => (
                      <div
                        key={opt.id}
                        className={`p-2 rounded-md border ${
                          opt.id === q.correct_option_id
                            ? "bg-green-100 border-green-400"
                            : "border-base-300"
                        }`}
                      >
                        {opt.text}
                      </div>
                    ))}
                  </div>
                )}

                {q.question_type === "true_false" && (
                  <div className="mt-2 space-x-4">
                    <span
                      className={`badge ${
                        q.correct_answer === true ? "badge-success" : "badge-outline"
                      }`}
                    >
                      True
                    </span>
                    <span
                      className={`badge ${
                        q.correct_answer === false ? "badge-success" : "badge-outline"
                      }`}
                    >
                      False
                    </span>
                  </div>
                )}

                {q.question_type === "type_in" && (
                  <div className="mt-2">
                    <div className="badge badge-info">
                      Answer: {q.correct_answer}
                    </div>
                  </div>
                )}

                {q.tags && q.tags.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1 text-sm">
                    {q.tags.map((tag) => (
                      <span key={tag} className="badge badge-ghost badge-sm">
                        {tag}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        <div className="modal-action">
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </dialog>
  );
};

const statusColor = (status) => {
  switch (status) {
    case "published":
      return "success";
    case "draft":
      return "warning";
    case "archived":
      return "neutral";
    default:
      return "info";
  }
};

export default ViewQuizModal;
