import React from 'react';
import { LogOut, FileText, LayoutDashboard, Settings } from 'lucide-react';
import { useAuth } from '../context/AuthContext';

const Layout = ({ children }) => {
    const { logout, user } = useAuth();

    return (
        <div className="min-h-screen bg-slate-50 flex">
            {/* Sidebar */}
            <aside className="w-64 bg-white border-r border-slate-200 fixed h-full z-10 hidden md:flex flex-col">
                <div className="p-6 border-b border-slate-100">
                    <div className="flex items-center gap-3">
                        <div className="bg-primary-50 p-2 rounded-lg">
                            <FileText className="w-6 h-6 text-primary-600" />
                        </div>
                        <span className="text-xl font-bold text-slate-900">DocuMind</span>
                    </div>
                </div>

                <nav className="flex-1 p-4 space-y-1">
                    <a href="#" className="flex items-center gap-3 px-4 py-3 text-primary-700 bg-primary-50 rounded-lg font-medium">
                        <LayoutDashboard className="w-5 h-5" />
                        Dashboard
                    </a>
                    <a href="#" className="flex items-center gap-3 px-4 py-3 text-slate-600 hover:bg-slate-50 hover:text-slate-900 rounded-lg font-medium transition-colors">
                        <Settings className="w-5 h-5" />
                        Settings
                    </a>
                </nav>

                <div className="p-4 border-t border-slate-100">
                    <div className="flex items-center gap-3 px-4 py-3 mb-2">
                        <div className="w-8 h-8 rounded-full bg-primary-100 flex items-center justify-center text-primary-700 font-bold text-sm">
                            U
                        </div>
                        <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-slate-900 truncate">User</p>
                            <p className="text-xs text-slate-500 truncate">user@example.com</p>
                        </div>
                    </div>
                    <button
                        onClick={logout}
                        className="w-full flex items-center gap-2 px-4 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                    >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                    </button>
                </div>
            </aside>

            {/* Mobile Header */}
            <div className="md:hidden fixed w-full bg-white border-b border-slate-200 z-20 px-4 py-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <FileText className="w-6 h-6 text-primary-600" />
                    <span className="text-lg font-bold text-slate-900">DocuMind</span>
                </div>
                <button onClick={logout} className="text-slate-500 hover:text-slate-900">
                    <LogOut className="w-5 h-5" />
                </button>
            </div>

            {/* Main Content */}
            <main className="flex-1 md:ml-64 p-4 md:p-8 pt-20 md:pt-8">
                <div className="max-w-7xl mx-auto">
                    {children}
                </div>
            </main>
        </div>
    );
};

export default Layout;
