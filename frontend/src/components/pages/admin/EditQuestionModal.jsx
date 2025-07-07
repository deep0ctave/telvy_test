import React, { useState } from "react";

const EditQuestionModal = ({ question, onClose, onSave }) => {
  const [form, setForm] = useState({
    ...question,
    tags: question.tags?.join(", ") || "",
    options:
      question.question_type === "mcq"
        ? question.options || ["", ""]
        : question.question_type === "true_false"
        ? ["True", "False"]
        : [],
  });

  const [error, setError] = useState("");

  const handleChange = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleOptionChange = (i, value) => {
    const newOptions = [...form.options];
    newOptions[i] = value;
    setForm((prev) => ({ ...prev, options: newOptions }));
  };

  const addOption = () => {
    setForm((prev) => ({ ...prev, options: [...prev.options, ""] }));
  };

  const removeOption = (i) => {
    setForm((prev) => ({
      ...prev,
      options: prev.options.filter((_, idx) => idx !== i),
    }));
  };

  const validate = () => {
    if (!form.question_text.trim()) return "Question text is required";
    if (form.question_type === "mcq" && form.options.some((o) => o.trim() === ""))
      return "All options must be filled";
    if (form.question_type === "mcq" && !form.options.includes(form.correct_answer))
      return "Correct answer must match one of the options";
    if (form.question_type === "type_in" && !form.correct_answer.trim())
      return "Correct answer is required";
    return "";
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    const err = validate();
    if (err) return setError(err);

    onSave({
      ...form,
      tags: form.tags
        .split(",")
        .map((t) => t.trim())
        .filter((t) => t !== ""),
    });
    onClose();
  };

  return (
    <div className="modal modal-open">
      <div className="modal-box max-w-2xl overflow-y-auto max-h-[90vh]">
        <h3 className="text-xl font-bold mb-4">Edit Question</h3>

        {error && <div className="alert alert-error mb-4">{error}</div>}

        <form onSubmit={handleSubmit} className="space-y-4">
          <fieldset>
            <legend className="label">Question Text</legend>
            <textarea
              className="textarea textarea-bordered w-full"
              rows={3}
              value={form.question_text}
              onChange={(e) => handleChange("question_text", e.target.value)}
            />
          </fieldset>

          <fieldset>
            <legend className="label">Question Type</legend>
            <select
              className="select select-bordered w-full"
              value={form.question_type}
              onChange={(e) => {
                const type = e.target.value;
                setForm((prev) => ({
                  ...prev,
                  question_type: type,
                  options: type === "mcq" ? ["", ""] : type === "true_false" ? ["True", "False"] : [],
                  correct_answer: "",
                }));
              }}
            >
              <option value="mcq">Multiple Choice</option>
              <option value="true_false">True / False</option>
              <option value="type_in">Type In</option>
            </select>
          </fieldset>

          {["mcq", "true_false"].includes(form.question_type) && (
            <fieldset className="space-y-2">
              <legend className="label">Options</legend>
              {form.options.map((opt, i) => (
                <div key={i} className="flex gap-2">
                  <input
                    type="text"
                    className="input input-bordered w-full"
                    value={opt}
                    onChange={(e) => handleOptionChange(i, e.target.value)}
                  />
                  {form.question_type === "mcq" && (
                    <button
                      type="button"
                      className="btn btn-sm btn-error"
                      onClick={() => removeOption(i)}
                      disabled={form.options.length <= 2}
                    >
                      ✕
                    </button>
                  )}
                </div>
              ))}
              {form.question_type === "mcq" && (
                <button type="button" className="btn btn-sm btn-outline" onClick={addOption}>
                  + Add Option
                </button>
              )}
            </fieldset>
          )}

          <fieldset>
            <legend className="label">Correct Answer</legend>
            <input
              type="text"
              className="input input-bordered w-full"
              value={form.correct_answer}
              onChange={(e) => handleChange("correct_answer", e.target.value)}
              placeholder={
                form.question_type === "type_in" ? "Type the correct answer" : "Must match an option"
              }
            />
          </fieldset>

          <fieldset>
            <legend className="label">Tags (comma-separated)</legend>
            <input
              type="text"
              className="input input-bordered w-full"
              value={form.tags}
              onChange={(e) => handleChange("tags", e.target.value)}
            />
          </fieldset>

          <div className="modal-action justify-end mt-6">
            <button type="button" className="btn" onClick={onClose}>
              Cancel
            </button>
            <button type="submit" className="btn btn-primary">
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default EditQuestionModal;
