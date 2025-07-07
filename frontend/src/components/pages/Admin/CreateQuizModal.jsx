// File: components/pages/Admin/CreateQuizModal.jsx
import React, { useState } from "react";
import { createFullQuiz } from "../../../services/api";
import { toast } from "react-toastify";

const defaultQuestion = {
  question_text: "",
  question_type: "mcq",
  tags: [],
  options: [{ text: "", is_correct: false }],
};

const CreateQuizModal = ({ onClose, onCreate }) => {
  const [form, setForm] = useState({
    title: "",
    description: "",
    image_url: "",
    quiz_type: "anytime",
    time_limit: 600,
    tags: [],
    questions: [],
  });

  const handleAddQuestion = () => {
    setForm((prev) => ({
      ...prev,
      questions: [...prev.questions, { ...defaultQuestion }],
    }));
  };

  const handleQuestionChange = (index, key, value) => {
    const updated = [...form.questions];
    updated[index][key] = value;
    setForm((prev) => ({ ...prev, questions: updated }));
  };

  const handleOptionChange = (qIdx, oIdx, key, value) => {
    const updated = [...form.questions];
    updated[qIdx].options[oIdx][key] = value;
    setForm((prev) => ({ ...prev, questions: updated }));
  };

  const handleAddOption = (qIdx) => {
    const updated = [...form.questions];
    updated[qIdx].options.push({ text: "", is_correct: false });
    setForm((prev) => ({ ...prev, questions: updated }));
  };

  const handleSubmit = async () => {
    if (!form.title.trim()) return toast.error("Quiz title is required");

    try {
      const payload = {
        ...form,
        tags: form.tags.filter(Boolean),
        questions: form.questions.map((q) => ({
          ...q,
          options: q.question_type === "mcq" || q.question_type === "true_false"
            ? q.options
            : undefined,
          accepted_answers: q.question_type === "type_in"
            ? q.accepted_answers || []
            : undefined,
        })),
      };
      const { data } = await createFullQuiz(payload);
      onCreate({ ...form, id: data.quiz_id });
    } catch (err) {
      toast.error(err?.response?.data?.message || "Failed to create quiz");
    }
  };

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-4xl">
        <h2 className="text-xl font-bold mb-4">Create Quiz</h2>

        <div className="space-y-3">
          <label className="input">
            <span className="label">Title</span>
            <input
              value={form.title}
              onChange={(e) => setForm({ ...form, title: e.target.value })}
            />
          </label>

          <label className="input">
            <span className="label">Description</span>
            <input
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </label>

          <label className="input">
            <span className="label">Image URL</span>
            <input
              value={form.image_url}
              onChange={(e) => setForm({ ...form, image_url: e.target.value })}
            />
          </label>

          <label className="input">
            <span className="label">Tags (comma-separated)</span>
            <input
              value={form.tags.join(", ")}
              onChange={(e) =>
                setForm({ ...form, tags: e.target.value.split(",").map((t) => t.trim()) })}
            />
          </label>

          <label className="input">
            <span className="label">Time Limit (seconds)</span>
            <input
              type="number"
              value={form.time_limit}
              onChange={(e) => setForm({ ...form, time_limit: +e.target.value })}
            />
          </label>

          <div className="flex items-center gap-4">
            <label className="label">Quiz Type</label>
            <select
              className="select select-bordered"
              value={form.quiz_type}
              onChange={(e) => setForm({ ...form, quiz_type: e.target.value })}
            >
              <option value="anytime">Anytime</option>
              <option value="scheduled">Scheduled</option>
            </select>
          </div>

          <div className="mt-6">
            <h3 className="font-bold">Questions</h3>
            {form.questions.map((q, i) => (
              <div key={i} className="border p-4 mt-2 rounded space-y-2 bg-base-100">
                <label className="input">
                  <span className="label">Question Text</span>
                  <input
                    value={q.question_text}
                    onChange={(e) => handleQuestionChange(i, "question_text", e.target.value)}
                  />
                </label>

                <label className="input">
                  <span className="label">Tags (comma-separated)</span>
                  <input
                    value={q.tags?.join(", ")}
                    onChange={(e) =>
                      handleQuestionChange(i, "tags", e.target.value.split(",").map((t) => t.trim()))
                    }
                  />
                </label>

                <div className="flex gap-4 items-center">
                  <label className="label">Type</label>
                  <select
                    className="select select-bordered"
                    value={q.question_type}
                    onChange={(e) =>
                      handleQuestionChange(i, "question_type", e.target.value)
                    }
                  >
                    <option value="mcq">MCQ</option>
                    <option value="true_false">True / False</option>
                    <option value="type_in">Type-in</option>
                  </select>
                </div>

                {q.question_type === "type_in" ? (
                  <label className="input">
                    <span className="label">Accepted Answers (comma-separated)</span>
                    <input
                      value={q.accepted_answers?.join(", ") || ""}
                      onChange={(e) =>
                        handleQuestionChange(i, "accepted_answers", e.target.value.split(",").map(s => s.trim()))
                      }
                    />
                  </label>
                ) : (
                  <>
                    <h4 className="font-semibold mt-2">Options</h4>
                    {q.options.map((opt, j) => (
                      <div key={j} className="flex gap-2 items-center">
                        <input
                          className="input input-bordered w-full"
                          placeholder={`Option ${j + 1}`}
                          value={opt.text}
                          onChange={(e) => handleOptionChange(i, j, "text", e.target.value)}
                        />
                        <input
                          type="checkbox"
                          checked={opt.is_correct}
                          onChange={(e) =>
                            handleOptionChange(i, j, "is_correct", e.target.checked)
                          }
                        />
                        <span className="text-sm">Correct</span>
                      </div>
                    ))}
                    <button
                      className="btn btn-sm btn-outline mt-1"
                      onClick={() => handleAddOption(i)}
                    >
                      + Add Option
                    </button>
                  </>
                )}
              </div>
            ))}

            <button className="btn btn-outline mt-4" onClick={handleAddQuestion}>
              + Add Question
            </button>
          </div>
        </div>

        <div className="modal-action">
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn btn-primary" onClick={handleSubmit}>Create</button>
        </div>
      </div>
    </div>
  );
};

export default CreateQuizModal;
