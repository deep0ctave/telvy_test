// File: components/pages/Admin/UserList.jsx

import React, { useState, useEffect } from "react";
import { Pencil, Trash2, ChevronUp, ChevronDown, Filter } from "lucide-react";
import CreateUserModal from "./CreateUserModal";
import EditUserModal from "./EditUserModal";
import DeleteUserModal from "./DeleteUserModal";
import {
  getAllUsers,
  createUser,
  updateUserById,
  deleteUserById,
} from "../../../services/api";
import { toast } from "react-toastify";

const UserList = () => {
  const [users, setUsers] = useState([]);
  const [filteredUsers, setFilteredUsers] = useState([]);
  const [search, setSearch] = useState("");
  const [advancedSearch, setAdvancedSearch] = useState(false);
  const [filters, setFilters] = useState({
    name: "",
    username: "",
    class: "",
    section: "",
    school: "",
    user_type: "",
  });
  const [sortConfig, setSortConfig] = useState({ key: "", direction: "asc" });

  const [showCreate, setShowCreate] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    fetchUsers();
  }, []);

  useEffect(() => {
    filterAndSortUsers();
  }, [search, filters, sortConfig, users]);

  const fetchUsers = async () => {
    try {
      const res = await getAllUsers();
      setUsers(res);
    } catch (err) {
      toast.error("Failed to fetch users");
    }
  };

  const filterAndSortUsers = () => {
    let data = [...users];

    if (search.trim()) {
      const s = search.toLowerCase();
      data = data.filter(
        (u) =>
          u.name?.toLowerCase().includes(s) ||
          u.username?.toLowerCase().includes(s) ||
          u.phone?.includes(s)
      );
    }

    if (advancedSearch) {
      for (const key in filters) {
        const val = filters[key].trim().toLowerCase();
        if (val) {
          data = data.filter((u) =>
            u[key]?.toLowerCase().includes(val)
          );
        }
      }
    }

    if (sortConfig.key) {
      const { key, direction } = sortConfig;
      data.sort((a, b) => {
        const aVal = a[key]?.toLowerCase?.() || "";
        const bVal = b[key]?.toLowerCase?.() || "";
        return direction === "asc"
          ? aVal.localeCompare(bVal)
          : bVal.localeCompare(aVal);
      });
    }

    setFilteredUsers(data);
  };

  const toggleSort = (key) => {
    setSortConfig((prev) => ({
      key,
      direction: prev.key === key && prev.direction === "asc" ? "desc" : "asc",
    }));
  };

  const handleDelete = async () => {
    try {
      await deleteUserById(selectedUser.id);
      setUsers((prev) => prev.filter((u) => u.id !== selectedUser.id));
      toast.success("User deleted");
      setShowDelete(false);
    } catch (err) {
      toast.error("Failed to delete user");
    }
  };

  const badgeColor = (type) => {
    if (type === "admin") return "badge-neutral";
    if (type === "teacher") return "badge-primary";
    return "badge-accent";
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex flex-wrap justify-between items-center gap-4">
        <h1 className="text-2xl font-bold">Manage Users</h1>
        <div className="flex gap-2">
          <button
            className="btn btn-outline"
            onClick={() => setAdvancedSearch((s) => !s)}
          >
            <Filter className="w-4 h-4" /> Advanced Search
          </button>
          <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
            + Create User
          </button>
        </div>
      </div>

      <input
        type="text"
        className="input input-bordered w-full max-w-md"
        placeholder="Search by name, username, or phone..."
        value={search}
        onChange={(e) => setSearch(e.target.value)}
      />

      {advancedSearch && (
        <div className="grid md:grid-cols-3 gap-4 bg-base-200 p-4 rounded-md">
          {Object.keys(filters).map((key) => (
            <input
              key={key}
              type="text"
              className="input input-bordered"
              placeholder={`Filter by ${key}`}
              value={filters[key]}
              onChange={(e) =>
                setFilters((prev) => ({ ...prev, [key]: e.target.value }))
              }
            />
          ))}
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="table table-zebra w-full">
          <thead>
            <tr>
              {[
                "username",
                "name",
                "phone",
                "user_type",
                "school",
                "class",
                "section",
                "dob",
              ].map((col) => (
                <th key={col} onClick={() => toggleSort(col)} className="cursor-pointer">
                  <div className="flex items-center gap-1 capitalize">
                    {col}
                    {sortConfig.key === col &&
                      (sortConfig.direction === "asc" ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      ))}
                  </div>
                </th>
              ))}
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredUsers.length === 0 ? (
              <tr>
                <td colSpan="99" className="text-center text-base-content/60 py-4">
                  No matching users found.
                </td>
              </tr>
            ) : (
              filteredUsers.map((u) => (
                <tr key={u.id}>
                  <td>{u.username}</td>
                  <td>{u.name}</td>
                  <td>{u.phone}</td>
                  <td>
                    <span className={`badge ${badgeColor(u.user_type)}`}>
                      {u.user_type}
                    </span>
                  </td>
                  <td>{u.school}</td>
                  <td>{u.class}</td>
                  <td>{u.section}</td>
                  <td>
                    {u.dob
                      ? new Date(u.dob).toLocaleDateString("en-GB")
                      : "-"}
                  </td>
                  <td className="flex gap-2">
                    <button
                      className="btn btn-sm btn-info"
                      onClick={() => {
                        setSelectedUser(u);
                        setShowEdit(true);
                      }}
                    >
                      <Pencil className="w-4 h-4" />
                    </button>
                    <button
                      className="btn btn-sm btn-error"
                      onClick={() => {
                        setSelectedUser(u);
                        setShowDelete(true);
                      }}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreate={(user) => {
            setUsers((prev) => [...prev, user]);
            toast.success("User created successfully");
          }}
        />
      )}

      {showEdit && selectedUser && (
        <EditUserModal
          user={selectedUser}
          onClose={() => {
            setSelectedUser(null);
            setShowEdit(false);
          }}
          onSave={(updated) => {
            setUsers((prev) =>
              prev.map((u) => (u.id === updated.id ? updated : u))
            );
          }}
        />
      )}

      {showDelete && selectedUser && (
        <DeleteUserModal
          user={selectedUser}
          onClose={() => setShowDelete(false)}
          onConfirm={handleDelete}
        />
      )}
    </div>
  );
};

export default UserList;
