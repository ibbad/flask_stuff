from flask import Blueprint, request, redirect, render_template, url_for
from flask.views import MethodView

from flask.ext.mongoengine.wtf import model_form

from tumblelog.auth import requires_auth
from tumblelog.models import Post, Comment, BlogPost, Video, Image, Quote

admin = Blueprint('admin', __name__, template_folder='templates')

class List(MethodView):
    decorators = [requires_auth]
    cls = Post

    def get(self):
        posts = self.cls.objects.all()
        return render_template('admin/list.html', posts=posts)

class Detail(MethodView):
    decorators = [requires_auth]

    # Mapping post types to models
    class_map = {
        'post': BlogPost,
        'video': Video,
        'image': Image,
        'quote': Quote,
    }

    def get_context(self, slug=None):

        if slug:
            post = Post.objects.get_or_404(slug=slug)
            # handle old types as well as new
            cls = post.__class__ if post.__class__ != Post else BlogPost
            form_cls = model_form(Post, exclude=('created_at', 'comments'))
            if request.method == 'POST':
                form = form_cls(request.form, initial=post._data)
            else:
                form = form_cls(obj=post)
        else:
            # Delete the post type
            cls = self.class_map.get(request.args.get('type', 'post'))
            post = cls()
            form_cls = model_form(cls, exclude=('created_at', 'comments'))
            form = form_cls(request.form)

        context = {
            "post": post,
            "form": form,
            "create": slug is None
        }

        return context

    def get(self, slug):
        context = self.get_context(slug)
        return render_template('admin/detail.html', **context)

    def post(self, slug):
        context = self.get_context(slug)
        form = context.get('form')

        if form.validate():
            post = context.get('post')
            form.populate_obj(post)
            post.save()

            return redirect(url_for('admin.index'))

        return render_template('admin/detail.html', **context)

# Register the urls
admin.add_url_rule('/admin', view_func=List.as_view('index'))
admin.add_url_rule('/admin/create/', defaults={'slug': None}, view_func=Detail.as_view('create'))
admin.add_url_rule('/admin/<slug>', view_func=Detail.as_view('edit'))
